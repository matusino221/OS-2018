JOS - MIT 2018 lab4

## Časť A --- SMP a kooperatívny multitasking
### Úloha 1: Implementujte funkciu 'mmio_map_region()' v súbore 'kern/pmap.c'. Ak chcete vidieť, ako sa používa jej volanie, pozrite sa na začiatok funkcie 'lapic_init()' v súbore 'kern/lapic.c'.
```c
void *
mmio_map_region(physaddr_t pa, size_t size)
{
...
	// Your code here:
	size_t n = ROUNDUP(size, PGSIZE);
	uintptr_t ret;
	if (base + n > MMIOLIM)
		panic("mmio_map_region: mapped region overflows MMIOLIM");
	boot_map_region(kern_pgdir, base, n, pa, PTE_P | PTE_W | PTE_PCD | PTE_PWT);
	ret = base;
	base += n;
	return (void*)ret;
}
```

### Úloha 2: Modifikujte implementáciu 'page_init()' v 'kern/pmap.c' tak, aby ste nepridali pamäťový rámec na adrese 'MPENTRY_ADDR' do zoznamu voľných rámcov fyzickej pamäte. Všimnite si poznámky k funkcii, a riaďte sa nimi.
```c
void
page_init(void)
{
... // 3 podmienka || je pridana
	for (i = 0; i < npages; i++) {
		pa = page2pa(&pages[i]); //prevediem si stranku na fyzicku adresu
		va = page2kva(&pages[i]); // prevediem si stranku na adresu kernelu 
		if ( (i==0) || ( IOPHYSMEM <= pa + PGSIZE && va < (char *) boot_alloc(0) ) || (MPENTRY_PADDR <= pa && pa < MPENTRY_PADDR + PGSIZE) ){ // i=0 je pripad 1)  a druhy pripad je diera od IOPHYSMEM  po adresu jadra ( ako zistim adresu jadra ? boot_alloc(0) ) samozrejme musim porovnavat rovnake typy
			pages[i].pp_ref = 1;
			pages[i].pp_link = NULL;
		}else {
			pages[i].pp_ref = 0;
			pages[i].pp_link = page_free_list;
			page_free_list = &pages[i];
		}
	}
}
```
### Úloha 3: Modifikujte 'mem_init_mp()' v súbore 'kern/pmap.c' tak, aby sa správne namapoval každému CPU jeho vlastný zásobník jadra (počnúc adresou 'KSTACKTOP' podľa schémy uvedenej v 'inc/memlayout.h'). Veľkosť každého zásobníka je 'KSTKSIZE' bajtov a medzi zásobníkmi má byť vždy medzera o veľkosti 'KSTKGAP' bajtov (nenamapovaný priestor).
```c
static void
mem_init_mp(void)
{
...
	// LAB 4: Your code here:
	uint32_t kstacktop_i;
	for(int i = 0; i < NCPU; i++) {
		kstacktop_i = KSTACKTOP - i * (KSTKSIZE + KSTKGAP);
		boot_map_region(kern_pgdir, kstacktop_i - KSTKSIZE, KSTKSIZE, PADDR(percpu_kstacks[i]), (PTE_P | PTE_W));
	}
}
```
### Úloha 4: Aktuálny kód v 'kern/trap.c' inicializuje TSS a TSS deskriptor pre BSP. To nám doteraz postačovalo, avšak pre inicializáciu aplikačných procesorov je takýto prístup nesprávny (a nefunkčný). Zmeňte tento kód tak, aby bol funkčný (a správny) pre všetky procesory.
```c
void
trap_init_percpu(void)
{
...
	// LAB 4: Your code here:
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	int cid = thiscpu->cpu_id;
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - cid * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	//ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3)+cid] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)), sizeof(struct Taskstate) -1, 0);
	gdt[(GD_TSS0 >> 3)+cid].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0+8*cid);

	// Load the IDT
	lidt(&idt_pd);
}
```
### Úloha 5: Aplikujte veľký zámok jadra podľa popisu uvedeného vyššie (umiestnením volaní 'lock_kernel()' a 'unlock_kernel()' na príslušných miestach v zdrojákoch).
### V 'i386_init()' zamknite zámok predtým, než BSP prebudí ostatné procesory.
### V 'mp_main()' zamknite zámok po inicializácii AP, a hneď potom zavolajte funkciu 'sched_yield()', ktorá spustí na tomto AP nejaké prostredie užívateľa čakajúce na spustenie (ak také je).
### Vo funkcii 'trap()' zamknite zámok pri príchode prerušenia v užívateľskom priestore. Na rozhodnutie, či prerušenie nastalo v užívateľskom priestore alebo v priestore jadra, využite spodné dva bity registra 'tf_cs'.
### Vo funkcii 'env_run()' uvoľnite zámok tesne pred prepnutím sa do užívateľského priestoru. Nesmiete to urobiť príliš skoro alebo príliš neskoro, pretože v jednom prípade vytvoríte priestor na súbehy (angl. race conditions) a v druhom uviaznutie (angl. deadlock).
```c
void
i386_init(void)
{
...
	// Acquire the big kernel lock before waking up APs
	// Your code here:
	lock_kernel();
...
}

void
mp_main(void)
{
...
	// Now that we have finished some basic setup, call sched_yield()
	// to start running processes on this CPU.  But make sure that
	// only one CPU can enter the scheduler at a time!
	//
	// Your code here:
	lock_kernel();
	sched_yield();
	// Remove this after you finish Exercise 6
	//for (;;);
}

void
trap(struct Trapframe *tf)
{
...
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();
		assert(curenv);
...
}

void
env_run(struct Env *e)
{
...
	lcr3(PADDR(curenv->env_pgdir));
	unlock_kernel();
	env_pop_tf(&(curenv->env_tf));
}

```
### Úloha 6: Implementujte plánovač typu Round-Robin vo funkcii 'sched_yield()' podľa popisu uvedeného vyššie. Nezabudnite modifikovať 'syscall()' tak, aby sa spúšťala funkcia 'sys_yield()', ak o to užívateľ systémovým volaním požiada. Taktiež sa uistite, že ste pridali volanie funkcie 'sched_yield()' do 'mp_main()' na koniec. Modifikujte 'kern/init.c' tak, aby sa vytvorili a spustili aspoň tri prostredia 'user/yield.c'.
```c
void
sched_yield(void)
{
	struct Env *idle;
...
	// LAB 4: Your code here.
	int index = curenv ? (ENVX(curenv->env_id)+1) % NENV : 0;
	idle = NULL;
	for (int i=0;i < NENV; i++){
		if(envs[(index+i) % NENV].env_status == ENV_RUNNABLE){
			idle = &envs[(index+i)%NENV];
			break;
		}
		
	}
	if (idle)
		env_run(idle);
	if(curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	// sched_halt never returns
	sched_halt();
}
```
### Úloha 7: V súbore 'kern/syscall.c' implementujte vyššie spomínané systémové volania sys_exofork(), sys_env_set_status() , sys_page_alloc() , sys_page_map() , sys_page_unmap()
 ```c
static envid_t
sys_exofork(void)
{
...
	// LAB 4: Your code here.
	int r;
	struct Env *e;
	if ((r = env_alloc(&e, curenv->env_id)) < 0)
		return r;
	e->env_status = ENV_NOT_RUNNABLE;
	e->env_tf = curenv->env_tf;
	e->env_tf.tf_regs.reg_eax = 0;
	return e->env_id;
}

static int
sys_env_set_status(envid_t envid, int status)
{
...
	// LAB 4: Your code here.
	int r;
	struct Env *e;

	if(status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE)
		return -E_INVAL;
	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	e->env_status = status;
	return 0;
}

static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
...
	// LAB 4: Your code here.
	int r;
	struct Env *e;
	struct PageInfo *pp;

	if ((uint32_t)va >= UTOP || (((uint32_t)va & 0xFFF) != 0))
		return -E_INVAL;
	if ((perm | PTE_SYSCALL) != PTE_SYSCALL)
		return -E_INVAL;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;

	pp = page_alloc(ALLOC_ZERO);
	if(pp == NULL)
		return -E_NO_MEM;

	if((r = page_insert(e->env_pgdir, pp, va, perm)) < 0)
	{
		page_free(pp);
		return r;
	}
	return 0;
}

static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
...
	// LAB 4: Your code here.
	//panic("sys_page_map not implemented");
	int r;
	struct Env *src_env, *dst_env;
	struct PageInfo *pp;
	pte_t *ptep;
	if ((r = envid2env(srcenvid, &src_env, 1)) < 0)
		return r;
	if ((r = envid2env(dstenvid, &dst_env, 1)) < 0)
		return r;
	if ((uint32_t)srcva >= UTOP || (((uint32_t)srcva & 0xFFF) != 0))
		return -E_INVAL;
	if ((uint32_t)dstva >= UTOP || (((uint32_t)dstva & 0xFFF) != 0))
		return -E_INVAL;
	if ((perm | PTE_SYSCALL) != PTE_SYSCALL)
		return -E_INVAL;

	pp = page_lookup(src_env->env_pgdir, srcva, &ptep);
	if (pp == NULL)
		return -E_INVAL;
	if (!((*ptep) & PTE_W) && (perm & PTE_W))
		return -E_INVAL;
	if ((r = page_insert(dst_env->env_pgdir, pp, dstva, perm)) < 0)
		return r;
	return 0;
}

static int
sys_page_unmap(envid_t envid, void *va)
{
...
	// LAB 4: Your code here.
	//panic("sys_page_unmap not implemented");
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	if ((uint32_t)va >= UTOP || (((uint32_t)va & 0xFFF) != 0))
		return -E_INVAL;
	page_remove(e->env_pgdir, va);
	return 0;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
...
	// LAB 3: Your code here.

	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((char *)a1, a2);
			return 0;
		case SYS_cgetc:
			return sys_cgetc();
		case SYS_getenvid:
			return sys_getenvid();
		case SYS_env_destroy:
			return sys_env_destroy(a1);
		case SYS_page_alloc:
			return sys_page_alloc((envid_t)a1, (void *)a2, (int)a3);
		case SYS_page_map:
			return sys_page_map((envid_t)a1, (void *)a2, (envid_t)a3, (void *)a4, (int)a5);
		case SYS_page_unmap:
			return sys_page_unmap((envid_t)a1, (void *)a2);
		case SYS_exofork:
			return sys_exofork();
		case SYS_env_set_status:
			return sys_env_set_status((envid_t)a1, (int)a2);
		case SYS_env_set_pgfault_upcall:
			return sys_env_set_pgfault_upcall((envid_t)a1, (void *)a2);
		case SYS_yield:
			sys_yield();
		case SYS_ipc_try_send:
			return sys_ipc_try_send((envid_t)a1, (uint32_t)a2, (void *)a3, (unsigned)a4);
		case SYS_ipc_recv:
			return sys_ipc_recv((void *)a1);
		default:
			return -E_INVAL;
	}
}
```
## Časť B: fork Copy-On-Write
### Úloha 1: Implementujte systémové volanie 'sys_env_set_pgfault_upcall()' podľa pokynov v komentároch.
 ```c
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *e;
	int ret = envid2env(envid, &e, 1);
	if (ret)
		return -E_BAD_ENV;
	
	e->env_pgfault_upcall = func;
	return 0;
}
```
### Úloha 2: Implementujte kód funkcie 'page_fault_handler()' v 'kern/trap.c' tak, aby ste presmerovali vykonanie obsluhy do užívateľského priestoru, ak je nejaká obsluha v užívateľskom priestore registrovaná. Riaďte sa pokynmi v komentároch.
```c
void
page_fault_handler(struct Trapframe *tf)
{
...
	// LAB 4: Your code here.
	if(curenv->env_pgfault_upcall){
		size_t size = sizeof(struct UTrapframe);
		struct UTrapframe *utf = (struct UTrapframe*) (UXSTACKTOP-size);
		
		if(tf->tf_esp > USTACKTOP){
			size +=4;
			utf = (struct UTrapframe*) (tf->tf_esp - size);
		}
		
		user_mem_assert(curenv, (void*) utf, size, PTE_W | PTE_U | PTE_P );
		
		utf->utf_fault_va = fault_va;
		utf->utf_err = tf->tf_err;
		utf->utf_regs = tf->tf_regs;
		utf->utf_eip = tf->tf_eip;
		utf->utf_eflags = tf->tf_eflags;
		utf->utf_esp = tf->tf_esp;
		
		tf->tf_esp = (uint32_t) utf;
		tf->tf_eip = (uint32_t) curenv->env_pgfault_upcall;
		env_run(curenv);
	}
...
}
```
### Úloha 3: Skopírujte si súbor pfentry.S, v ktorom sa nachádza predpripravená implementácia funkcie '_pgfault_upcall()'.

### Úloha 4: Dokončite implementáciu funkcie 'set_pgfault_handler()' v 'lib/pgfault.c' podľa pokynov v komentároch.
```c
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
	int r;

	if (_pgfault_handler == 0) {
		// First time through!
		// LAB 4: Your code here.
		if((sys_page_alloc(0, (void *)(UXSTACKTOP-PGSIZE), PTE_U | PTE_W | PTE_P) < 0))
			panic("set_pgfault_handler: sys_page_alloc error\n");

		if((sys_env_set_pgfault_upcall(0, _pgfault_upcall)) < 0)
			panic("set_pgfault_handler: sys_env_set_pgfault_upcall error\n");
	}

	// Save handler pointer for assembly to call.
	_pgfault_handler = handler;
}
```
### Úloha 5: Implementujte funkcie 'fork()', 'duppage()' a 'pgfault()' v súbore 'lib/fork.c'.
```c
envid_t
fork(void)
{
	// LAB 4: Your code here.
	set_pgfault_handler(pgfault);
	envid_t envid = sys_exofork();
	if(envid <0)
		panic("sys_exofork: %e",envid);
	if(envid == 0){
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
		
	}
	for(int pn = 0; pn < PGNUM(UTOP); pn++){
		if(pn==PGNUM(UXSTACKTOP-PGSIZE))
			continue;
		if ((uvpd[pn >> 10] & PTE_P) && (uvpt[pn] & PTE_P))
			duppage(envid, pn);
	}
	
	int r = sys_page_alloc(envid, (void*)(UXSTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W);
	if (r)
		panic("sys_page_alloc: %e", r);
	extern void _pgfault_upcall(void);
	 r = sys_env_set_pgfault_upcall(envid, (void*) _pgfault_upcall);
	 if(r)
		 panic("sys_page_alloc: %e", r);
	
	// Start the child environment running
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);
	return envid;
}

static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void* addr = (void *)(pn * PGSIZE);
	if((uvpt[pn] & PTE_COW) || (uvpt[pn] & PTE_W))
	{
		r = sys_page_map(0, addr, envid, addr, PTE_COW | PTE_U | PTE_P);
		if(r < 0)
			panic("duppage: sys_page_map fail\n");
		r = sys_page_map(0, addr, 0, addr, PTE_COW | PTE_U | PTE_P);
		if(r < 0)
			panic("duppage: sys_page_map fail\n");
	}
	else
	{
		r = sys_page_map(0, addr, envid, addr, PTE_U | PTE_P);
		if(r < 0)
			panic("duppage: sys_page_map fail\n");
	}
	return 0;
}

static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if (!(err & FEC_WR) || !(uvpt[PGNUM(addr)] & PTE_COW))
		panic("not COW %x", addr);
	if (!(uvpt[PGNUM(addr)] & PTE_P))
		panic("not Present");
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	if ((r = sys_page_alloc(0, PFTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_alloc: %e", r);
	memmove(PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);
	if ((r = sys_page_map(0, PFTEMP, 0, ROUNDDOWN(addr, PGSIZE), PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_map: %e", r);
	if ((r = sys_page_unmap(0, PFTEMP)) < 0)
		panic("sys_page_unmap: %e", r);
}
```
## Časť C: Preemptívny multitasking a medziprocesová komunikácia (IPC)

### Úloha 1: Prepíšte si súbor 'kern/trapentry.S' touto novou verziou trapentry.S.

### Úloha 2: Modifikujte súbor 'kern/trap.c' tak, aby ste správne inicializovali potrebné položky tabuľky IDT. To znamená, aby ste správne registrovali rutiny na spracovanie externých prerušení IRQ 0 až 15. Zároveň skontrolujte registráciu všetkých predošlých obslužných rutín pre prerušenia procesora a pre spracovanie systémového volania, či sú im prislúchajúce deskriptory v IDT správne definované. Modifikujte taktiež kód funkcie 'env_alloc()' v 'kern/env.c' tak, aby sa užívateľské prostredie spustilo s nastaveným príznakom 'FL_IF' spracovania externých prerušení. Na záver odkomentujte inštrukciu 'sti' vo funkcii 'sched_halt()', aby ste umožnili zobudenie procesorov, ktoré sa touto funkciou uspia.
```c
void
trap_init(void)
{
... //								TU musi byt nula !!!
    //								|
	extern void TH_SYSCALL(); 	SETGATE(idt[T_SYSCALL], 0, GD_KT, TH_SYSCALL, 3); 
	// hardware interrupts
	extern void TH_IRQ_TIMER();	SETGATE(idt[IRQ_OFFSET], 0, GD_KT, TH_IRQ_TIMER, 0);
	extern void TH_IRQ_KBD();	SETGATE(idt[IRQ_OFFSET+1], 0, GD_KT, TH_IRQ_KBD, 0);
	extern void TH_IRQ_2();		SETGATE(idt[IRQ_OFFSET+2], 0, GD_KT, TH_IRQ_2, 0);
	extern void TH_IRQ_3();		SETGATE(idt[IRQ_OFFSET+3], 0, GD_KT, TH_IRQ_3, 0);
	extern void TH_IRQ_SERIAL();SETGATE(idt[IRQ_OFFSET+4], 0, GD_KT, TH_IRQ_SERIAL, 0);
	extern void TH_IRQ_5();		SETGATE(idt[IRQ_OFFSET+5], 0, GD_KT, TH_IRQ_5, 0);
	extern void TH_IRQ_6();		SETGATE(idt[IRQ_OFFSET+6], 0, GD_KT, TH_IRQ_6, 0);
	extern void TH_IRQ_SPURIOUS();SETGATE(idt[IRQ_OFFSET+7], 0, GD_KT, TH_IRQ_SPURIOUS, 0);
	extern void TH_IRQ_8();		SETGATE(idt[IRQ_OFFSET+8], 0, GD_KT, TH_IRQ_8, 0);
	extern void TH_IRQ_9();		SETGATE(idt[IRQ_OFFSET+9], 0, GD_KT, TH_IRQ_9, 0);
	extern void TH_IRQ_10();	SETGATE(idt[IRQ_OFFSET+10], 0, GD_KT, TH_IRQ_10, 0);
	extern void TH_IRQ_11();	SETGATE(idt[IRQ_OFFSET+11], 0, GD_KT, TH_IRQ_11, 0);
	extern void TH_IRQ_12();	SETGATE(idt[IRQ_OFFSET+12], 0, GD_KT, TH_IRQ_12, 0);
	extern void TH_IRQ_13();	SETGATE(idt[IRQ_OFFSET+13], 0, GD_KT, TH_IRQ_13, 0);
	extern void TH_IRQ_IDE();	SETGATE(idt[IRQ_OFFSET+14], 0, GD_KT, TH_IRQ_IDE, 0);
	extern void TH_IRQ_15();	SETGATE(idt[IRQ_OFFSET+15], 0, GD_KT, TH_IRQ_15, 0);

	// Per-CPU setup 
	trap_init_percpu();
}

int
env_alloc(struct Env **newenv_store, envid_t parent_id)
{
...
	// Enable interrupts while in user mode.
	// LAB 4: Your code here.
	e->env_tf.tf_eflags |= FL_IF;

...
}

void
sched_halt(void)
{
...
	// Reset stack pointer, enable interrupts and then halt.
	asm volatile (
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		// Uncomment the following line after completing exercise 13
		"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
	: : "a" (thiscpu->cpu_ts.ts_esp0));
}
```
### Úloha 3: Zmeňte funkciu 'trap_dispatch()' tak, aby sa pri vygenerovaní prerušenia časovača vyvolala funkcia 'sched_yield()'. Dobre si všimnite poznámku k úlohe v komentároch funkcie: pred volaním 'sched_yield()' musíte zavolať funkciu 'lapic_eoi()'.
```c
static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	switch (tf->tf_trapno) {
...
		case (IRQ_OFFSET + IRQ_SPURIOUS):
			cprintf("Spurious interrupt on irq 7\n");
			print_trapframe(tf);
			return;
		// Handle clock interrupts. Don't forget to acknowledge the
		// interrupt using lapic_eoi() before calling the scheduler!
		case (IRQ_OFFSET + IRQ_TIMER):
			lapic_eoi();
			sched_yield();
			return ;
		default:
			break;
	}
...
}
```
### Úloha 4: Implementujte systémové volania 'sys_ipc_recv()' a 'sys_ipc_try_send()' v súbore 'kern/syscall.c'.
```c
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	//panic("sys_ipc_recv not implemented");
	if (((uint32_t)dstva < UTOP) && (((uint32_t)dstva % PGSIZE) != 0))
		return -E_INVAL;

	curenv->env_ipc_recving = 1;
	curenv->env_ipc_dstva = dstva;
	curenv->env_status = ENV_NOT_RUNNABLE;
	sched_yield();
	return 0;
}

static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	//panic("sys_ipc_try_send not implemented");
	int r;
	struct Env *e;
	struct PageInfo *pp;
	pte_t *ptep;

	if ((r = envid2env(envid, &e, 0)) < 0)
		return r;
	if (e->env_ipc_recving == 0)
		return -E_IPC_NOT_RECV;

	e->env_ipc_perm = 0;
	if ((uintptr_t) srcva < UTOP) {
		if ((uint32_t)srcva % PGSIZE)
			return -E_INVAL;
		if (perm & ~PTE_SYSCALL)
			return -E_INVAL;
		if ((perm & (PTE_U | PTE_P)) != (PTE_U | PTE_P))
			return -E_INVAL;

		pp = page_lookup(curenv->env_pgdir, srcva, &ptep);
		if (!pp)
			return -E_INVAL;
		if (!(*ptep & PTE_W) && (perm & PTE_W))
			return -E_INVAL;

		if ((uint32_t)e->env_ipc_dstva < UTOP)
		{
			if ((r = page_insert(e->env_pgdir, pp, e->env_ipc_dstva, perm)) < 0)
				return r;
			e->env_ipc_perm = perm;
		}
	}
	e->env_ipc_recving = 0;
	e->env_ipc_value = value;
	e->env_ipc_from = curenv->env_id;
	e->env_status = ENV_RUNNABLE;
	e->env_tf.tf_regs.reg_eax = 0;
	return 0;
}
```
### Úloha 5: Implementujte knižničné funkcie 'ipc_recv()' a 'ipc_send()' v súbore 'lib/ipc.c'.
```c
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	// LAB 4: Your code here.
	if (pg == NULL)
		pg = (void *)UTOP;

	if (from_env_store != NULL)
		*from_env_store = 0;
	if (perm_store != NULL)
		*perm_store = 0;

	int r = sys_ipc_recv(pg);
	if (r < 0)
		return r;

	if (from_env_store != NULL)
		*from_env_store = thisenv->env_ipc_from;
	if (perm_store != NULL)
		*perm_store = thisenv->env_ipc_perm;
	return thisenv->env_ipc_value;
}

void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	// LAB 4: Your code here.
	int r;
	if (pg == NULL)
		pg = (void *)UTOP;
	while(1) {
		r = sys_ipc_try_send(to_env, val, pg, perm);
		if (r == 0)
			break;
		if(r < 0 && r != -E_IPC_NOT_RECV)
			panic("ipc_send: send fail, %e\n", r);
		sys_yield();
	}
}
```
dumbfork: OK (1.5s) 

Part A score: 5/5

faultread: OK (1.9s) 

faultwrite: OK (2.1s) 

faultdie: OK (2.0s) 

faultregs: OK (2.0s) 

faultalloc: OK (1.9s) 

faultallocbad: OK (2.2s) 

faultnostack: OK (2.0s) 

faultbadhandler: OK (2.1s) 

faultevilhandler: OK (1.9s) 

forktree: OK (2.2s) 

Part B score: 50/50

spin: OK (2.0s) 

stresssched: OK (2.4s) 

sendpage: OK (2.1s) 

pingpong: OK (1.8s) 

primes: OK (4.9s) 

Part C score: 25/25

### Score: 80/80
