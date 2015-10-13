/*
 * Copyright (c) 2015 The Regents of the University of California
 * Valmon Leymarie <leymariv@berkeley.edu>
 * Kevin Klues <klueska@cs.berkeley.edu>
 * See LICENSE for details.
 */

#include <arch/topology.h>
#include <sys/queue.h>
#include <env.h>
#include <corerequest.h>
#include <kmalloc.h>

enum pnode_type { CORE, CPU, SOCKET, NUMA, MACHINE, NUM_NODE_TYPES};
static char pnode_label[5][8] = { "CORE", "CPU", "SOCKET", "NUMA", "MACHINE" };
#define UNKNOWN_PROC ((void*)-1)

struct sched_pnode {
	int id;
	enum pnode_type type;
	int refcount[NUM_NODE_TYPES];
	struct sched_pnode *parent;
	struct sched_pnode *children;
	struct sched_pcore *spc_data;
};

#define num_cpus            (cpu_topology_info.num_cpus)
#define num_sockets         (cpu_topology_info.num_sockets)
#define num_numa            (cpu_topology_info.num_numa)
#define cores_per_numa      (cpu_topology_info.cores_per_numa)
#define cores_per_socket    (cpu_topology_info.cores_per_socket)
#define cores_per_cpu       (cpu_topology_info.cores_per_cpu)
#define cpus_per_socket     (cpu_topology_info.cpus_per_socket)
#define cpus_per_numa       (cpu_topology_info.cpus_per_numa)
#define sockets_per_numa    (cpu_topology_info.sockets_per_numa)

#define child_node_type(t) ((t) - 1)
#define num_children(t) ((t) ? num_descendants[(t)][(t)-1] : 0)

#define get_node_id(core_info, level) \
	((level) == CPU     ? (core_info)->cpu_id : \
	 (level) == SOCKET  ? (core_info)->socket_id : \
	 (level) == NUMA    ? (core_info)->numa_id : \
	 (level) == MACHINE ? 1 : 0)

/* An array containing the number of nodes at each level. */
static int num_nodes[NUM_NODE_TYPES];

/* A 2D array containing for all core i its distance from a core j. */
static int **core_distance;

/* An array containing the number of children at each level. */
static int num_descendants[NUM_NODE_TYPES][NUM_NODE_TYPES];

/* A list of lookup tables to find specific nodes by type and id. */
static int total_nodes;
static struct sched_pnode *all_nodes;
static struct sched_pnode *node_lookup[NUM_NODE_TYPES];
struct sched_pcore *all_pcores;

/* Create a node and initialize it. */
static void init_nodes(int type, int num, int nchildren)
{
	/* Initialize the lookup tables for this node type. */
	num_nodes[type] = num;
	node_lookup[type] = all_nodes;
	for (int i = CORE; i < type; i++)
		node_lookup[type] += num_nodes[i];

	/* Initialize all fields of each node. */
	for (int i = 0; i < num; i++) {
		struct sched_pnode *n = &node_lookup[type][i];
		n->id = i;
		n->type = type;
		memset(n->refcount, 0, sizeof(n->refcount));
		n->parent = NULL;
		n->children = &node_lookup[child_node_type(type)][i * nchildren];
		for (int j = 0; j < nchildren; j++)
			n->children[j].parent = n;

		n->spc_data = NULL;
		if (n->type == CORE) {
			n->spc_data = &all_pcores[n->id];
			n->spc_data->spn = n;
			n->spc_data->spc_info = &cpu_topology_info.core_list[n->id];
			n->spc_data->alloc_proc = NULL;
			n->spc_data->prov_proc = NULL;
		}
	}
}

/* Allocate a flat array of array of int. It represent the distance from one
 * core to an other. If cores are on the same CPU, their distance is 2, if they
 * are on the same socket, their distance is 4, on the same numa their distance
 * is 6. Otherwise their distance is 8.*/
static void init_core_distances()
{
	core_distance = kzmalloc(num_cores * sizeof(int*), 0);
	if (core_distance == NULL)
		panic("Out of memory!\n");
	for (int i = 0; i < num_cores; i++) {
		core_distance[i] = kzmalloc(num_cores * sizeof(int), 0);
		if (core_distance[i] == NULL)
			panic("Out of memory!\n");
	}
	for (int i = 0; i < num_cores; i++) {
		for (int j = 0; j < num_cores; j++) {
			for (int k = CPU; k<= MACHINE; k++) {
				if (i/num_descendants[k][CORE] ==
					j/num_descendants[k][CORE]) {
					core_distance[i][j] = k;
					break;
				}
			}
		}
	}
}

/* Initialize any data assocaited with doing core allocation. */
void corealloc_init(void)
{
	/* Allocate a flat array of nodes. */
	total_nodes = num_cores + num_cpus + num_sockets + num_numa;
	void *nodes_and_cores = kmalloc(total_nodes * sizeof(struct sched_pnode) +
	                                num_cores * sizeof(struct sched_pcore), 0);
	all_nodes = nodes_and_cores;
	all_pcores = nodes_and_cores + total_nodes * sizeof(struct sched_pnode);

	/* Initialize the number of descendants from our cpu_topology info. */
	num_descendants[CPU][CORE] = cores_per_cpu;
	num_descendants[SOCKET][CORE] = cores_per_socket;
	num_descendants[SOCKET][CPU] = cpus_per_socket;
	num_descendants[NUMA][CORE] = cores_per_numa;
	num_descendants[NUMA][CPU] = cpus_per_numa;
	num_descendants[NUMA][SOCKET] = sockets_per_numa;
	num_descendants[MACHINE][CORE] = num_cores;
	num_descendants[MACHINE][CPU] = num_cpus;
	num_descendants[MACHINE][SOCKET] = num_sockets;
	num_descendants[MACHINE][NUMA] = num_numa;

	/* Initialize the nodes at each level in our hierarchy. */
	init_nodes(CORE, num_cores, 0);
	init_nodes(CPU, num_cpus, cores_per_cpu);
	init_nodes(SOCKET, num_sockets, cpus_per_socket);
	init_nodes(NUMA, num_numa, sockets_per_numa);

	/* Initialize our 2 dimensions array of core_distances */
	init_core_distances();

	/* Remove all even ll_cores from consideration for allocation. */
	for (int i = 0; i < num_cores; i++)
		if (is_ll_core(i))
			all_pcores[i].alloc_proc = UNKNOWN_PROC;

#ifdef CONFIG_DISABLE_SMT
	/* Remove all even cores from consideration for allocation. */
	assert(!(num_cores % 2));
	for (int i = 0; i < num_cores; i += 2)
		if (is_ll_core(i))
			all_pcores[i].alloc_proc = UNKNOWN_PROC;
#endif /* CONFIG_DISABLE_SMT */
}

/* Initialize any data associated with allocating cores to a process. */
void corealloc_proc_init(struct proc *p)
{
	TAILQ_INIT(&p->ksched_data.crd.alloc_me);
	TAILQ_INIT(&p->ksched_data.crd.prov_alloc_me);
	TAILQ_INIT(&p->ksched_data.crd.prov_not_alloc_me);
}

/* Returns the sum of the distances from one core to all of the cores in a list. */
static int cumulative_core_distance(struct sched_pcore_tailq cl,
                                    struct sched_pcore *c)
{
	int d = 0;
	struct sched_pcore *temp = NULL;
	TAILQ_FOREACH(temp, &cl, alloc_next) {
		d += core_distance[c->spc_info->core_id][temp->spc_info->core_id];
	}
	return d;
}

/* Returns the first core for the node n. */
static struct sched_pcore *first_core_in_node(struct sched_pnode *n)
{
	struct sched_pnode *first_child = n;
	while (first_child->type != CORE)
		first_child = &first_child->children[0];
	return first_child->spc_data;
}

/* Return the first provisioned core available. Otherwise, return NULL. */
static struct sched_pcore *find_first_provisioned_core(struct proc *p)
{
	return TAILQ_FIRST(&(p->ksched_data.crd.prov_not_alloc_me));
}

/* Returns the best first core to allocate for a proc which owns no core.
 * Return the core that is the farthest from the others's proc cores. */
static struct sched_pcore *find_first_core(struct proc *p)
{
	struct sched_pnode *n = NULL;
	struct sched_pnode *bestn = NULL;
	int best_refcount = 0;
	struct sched_pnode *siblings = node_lookup[MACHINE];
	int num_siblings = 0;

	struct sched_pcore *c = find_first_provisioned_core(p);
	if (c != NULL)
		return c;

	for (int i = MACHINE; i >= CORE; i--) {
		for (int j = 0; j < num_siblings; j++) {
			n = &siblings[j];
			if (n->refcount[CORE] == 0)
				return first_core_in_node(n);
			if (best_refcount == 0)
				best_refcount = n->refcount[CORE];
			if (n->refcount[CORE] <= best_refcount &&
				n->refcount[CORE] < num_descendants[i][CORE]) {
				best_refcount = n->refcount[CORE];
				bestn = n;
			}
		}
		if (i == CORE || bestn == NULL)
			break;
		siblings = bestn->children;
		num_siblings = num_children(i);
		best_refcount = 0;
		bestn = NULL;
	}
	return bestn->spc_data;
}

/* Return the closet core from the list of provisioned cores to other cores we
 * already own. This function is slightly different from find_closest_core in
 * the way we just need to check the cores itself, and don't need to check
 * other levels of the topology. If no cores are available we return NULL.*/
static struct sched_pcore *find_closest_provisioned_core(struct proc *p)
{
	int bestd = 0;
	struct sched_pcore_tailq core_prov_available =
	           p->ksched_data.crd.prov_not_alloc_me;
	struct sched_pcore_tailq core_alloc = p->ksched_data.crd.alloc_me;
	struct sched_pcore *bestc = NULL;
	struct sched_pcore *c = NULL;
	TAILQ_FOREACH(c, &core_prov_available, prov_next) {
		int sibd = cumulative_core_distance(core_alloc, c);
		if (bestd == 0 || sibd < bestd) {
			bestd = sibd;
			bestc = c;
		}
	}
	return bestc;
}

/* Consider first core provisioned proc by calling
 * find_best_provisioned_core(). Then check siblings of the cores the proc
 * already owns. Calculate for every possible node its
 * cumulative_core_distance() (sum of the distances from this core to all of
 * the cores the proc owns).  Allocate the core that has the lowest
 * core_distance.  This code assumes that the scheduler that uses it holds a
 * lock for the duration of the call. */
struct sched_pcore *find_closest_core(struct proc *p)
{
	struct sched_pcore *bestc = find_closest_provisioned_core(p);

	/* If we found an available provisioned core, return it. */
	if (bestc != NULL)
		return bestc;

	/* Otherwise, keep looking... */
	int bestd = 0;
	struct sched_pcore *c = NULL;
	int sibling_id = 0;
	struct sched_pcore_tailq core_owned = p->ksched_data.crd.alloc_me;

	for (int k = CPU; k <= MACHINE; k++) {
		TAILQ_FOREACH(c, &core_owned, alloc_next) {
			int nb_cores = num_descendants[k][CORE];
			int type_id = get_node_id(c->spc_info, k);
			for (int i = 0; i < nb_cores; i++) {
				sibling_id = i + nb_cores*type_id;
				struct sched_pcore *sibc = &all_pcores[sibling_id];
				if (sibc->alloc_proc == NULL) {
					int sibd = cumulative_core_distance(core_owned, sibc);
					if (bestd == 0 || sibd <= bestd) {
						/* If the core we have found has best core is
						 * provisioned by an other proc, we try to find an
						 * equivalent core (in terms of distance) and allocate
						 * this core instead. */
						if (sibd == bestd) {
							if (bestc->prov_proc != NULL &&
								sibc->prov_proc == NULL) {
								bestd = sibd;
								bestc = sibc;
							}
						} else {
							bestd = sibd;
							bestc = sibc;
						}
					}
				}
			}
		}
		if (bestc != NULL)
			return bestc;
	}
	return NULL;
}

/* Find the best core to allocate. If no cores are allocated yet, find one that
 * is as far from the cores allocated to other processes as possible.
 * Otherwise, find a core that is as close as possible to one of the other
 * cores we already own. */
struct sched_pcore *__find_best_core_to_alloc(struct proc *p)
{
	struct sched_pcore *c = NULL;
	if (TAILQ_FIRST(&(p->ksched_data.crd.alloc_me)) == NULL)
		c = find_first_core(p);
	else
		c = find_closest_core(p);
	return c;
}

/* Recursively incref a node from its level through its ancestors.  At the
 * current level, we simply check if the refcount is 0, if it is not, we
 * increment it to one. Then, for each other lower level of the array, we sum
 * the refcount of the children. */
static void incref_nodes(struct sched_pnode *n)
{
	int type;
	struct sched_pnode *p;
	while (n != NULL) {
		type = n->type;
		if (n->refcount[type] == 0) {
			n->refcount[type]++;
			p = n->parent;
			while (p != NULL) {
				p->refcount[type]++;
				p = p->parent;
			}
		}
		n = n->parent;
	}
}

/* Recursively decref a node from its level through its ancestors.  If the
 * refcount is not 0, we have to check if the refcount of every child of the
 * current node is 0 to decrement its refcount. */
static void decref_nodes(struct sched_pnode *n)
{
	int type;
	struct sched_pnode *p;
	while (n != NULL) {
		type = n->type;
		if ((type == CORE) || (n->refcount[child_node_type(type)] == 0)) {
			n->refcount[type]--;
			p = n->parent;
			while (p != NULL) {
				p->refcount[type]--;
				p = p->parent;
			}
		}
		n = n->parent;
	}
}

/* Track the pcore properly when it is allocated to p. This code assumes that
 * the scheduler that uses it holds a lock for the duration of the call. */
void __track_core_alloc(struct proc *p, uint32_t pcoreid)
{
	struct sched_pcore *spc;
	assert(pcoreid < num_cores);	/* catch bugs */
	spc = pcoreid2spc(pcoreid);
	assert(spc->alloc_proc != p);	/* corruption or double-alloc */
	spc->alloc_proc = p;
	/* if the pcore is prov to them and now allocated, move lists */
	if (spc->prov_proc == p) {
		TAILQ_REMOVE(&p->ksched_data.crd.prov_not_alloc_me, spc, prov_next);
		TAILQ_INSERT_TAIL(&p->ksched_data.crd.prov_alloc_me, spc, prov_next);
	}
	/* Actually allocate the core, removing it from the idle core list. */
	TAILQ_INSERT_TAIL(&p->ksched_data.crd.alloc_me, spc, alloc_next);
	incref_nodes(spc->spn);
}

/* Track the pcore properly when it is deallocated from p. This code assumes
 * that the scheduler that uses it holds a lock for the duration of the call.
 * */
void __track_core_dealloc(struct proc *p, uint32_t pcoreid)
{
	struct sched_pcore *spc;
	assert(pcoreid < num_cores);	/* catch bugs */
	spc = pcoreid2spc(pcoreid);
	spc->alloc_proc = NULL;
	/* if the pcore is prov to them and now deallocated, move lists */
	if (spc->prov_proc == p) {
		TAILQ_REMOVE(&p->ksched_data.crd.prov_alloc_me, spc, prov_next);
		/* this is the victim list, which can be sorted so that we pick the
		 * right victim (sort by alloc_proc reverse priority, etc).  In this
		 * case, the core isn't alloc'd by anyone, so it should be the first
		 * victim. */
		TAILQ_INSERT_HEAD(&p->ksched_data.crd.prov_not_alloc_me, spc,
		                  prov_next);
	}
	/* Actually dealloc the core, putting it back on the idle core list. */
	TAILQ_REMOVE(&(p->ksched_data.crd.alloc_me), spc, alloc_next);
	decref_nodes(spc->spn);
}

/* Bulk interface for __track_core_dealloc */
void __track_core_dealloc_bulk(struct proc *p, uint32_t *pc_arr,
                               uint32_t nr_cores)
{
	for (int i = 0; i < nr_cores; i++)
		__track_core_dealloc(p, pc_arr[i]);
}

/* Get an idle core from our pcore list and return its core_id. Don't
 * consider the chosen core in the future when handing out cores to a
 * process. This code assumes that the scheduler that uses it holds a lock
 * for the duration of the call. This will not give out provisioned cores. */
int __get_any_idle_core(void)
{
	struct sched_pcore *spc;
	int ret = -1;
	for (int i = 0; i < num_cores; i++) {
		struct sched_pcore *c = &all_pcores[i];
		if (spc->alloc_proc == NULL) {
			spc->alloc_proc = UNKNOWN_PROC;
			ret = spc->spc_info->core_id;
		}
	}
	return ret;
}

/* Detect if a pcore is idle or not. */
static bool __spc_is_idle(struct sched_pcore *spc)
{
	return (spc->alloc_proc == NULL);
}

/* Same as __get_any_idle_core() except for a specific core id. */
int __get_specific_idle_core(int coreid)
{
	struct sched_pcore *spc = pcoreid2spc(coreid);
	int ret = -1;
	assert((0 <= coreid) && (coreid < num_cores));
	if (__spc_is_idle(pcoreid2spc(coreid)) && !spc->prov_proc) {
		assert(!spc->alloc_proc);
		spc->alloc_proc = UNKNOWN_PROC;
		ret = coreid;
	}
	return ret;
}

/* Reinsert a core obtained via __get_any_idle_core() or
 * __get_specific_idle_core() back into the idlecore map. This code assumes
 * that the scheduler that uses it holds a lock for the duration of the call.
 * This will not give out provisioned cores. */
void __put_idle_core(int coreid)
{
	struct sched_pcore *spc = pcoreid2spc(coreid);
	assert((0 <= coreid) && (coreid < num_cores));
	spc->alloc_proc = NULL;
}

/* One off function to make 'pcoreid' the next core chosen by the core
 * allocation algorithm (so long as no provisioned cores are still idle).
 * This code assumes that the scheduler that uses it holds a lock for the
 * duration of the call. */
void __next_core_to_alloc(uint32_t pcoreid)
{
	printk("This function is not supported by this core allocation policy!\n");
}

/* One off function to sort the idle core list for debugging in the kernel
 * monitor. This code assumes that the scheduler that uses it holds a lock
 * for the duration of the call. */
void __sort_idle_cores(void)
{
	printk("This function is not supported by this core allocation policy!\n");
}

/* Print the map of idle cores that are still allocatable through our core
 * allocation algorithm. */
void print_idle_core_map(void)
{
	printk("Idle cores (unlocked!):\n");
	for (int i = 0; i < num_cores; i++) {
		struct sched_pcore *spc_i = &all_pcores[i];
		if (spc_i->alloc_proc == NULL)
			printk("Core %d, prov to %d (%p)\n", spc_i->spc_info->core_id,
			       spc_i->prov_proc ? spc_i->prov_proc->pid :
				   0, spc_i->prov_proc);
	}
}
