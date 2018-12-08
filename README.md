JOS - MIT 2018 lab3 

### Úloha 1: Modifikujte funkciu 'mem_init()' v súbore 'kern/pmap.c' tak, aby ste alokovali a vhodne namapovali do virtuálneho priestoru jadra pole 'envs'. Toto pole má pozostávať práve z 'NENV' prvkov štruktúr typu 'Env'. Alokujte ho podobne ako pole 'pages'. Taktiež namapujte pole 'envs' tak, aby sa mapovalo pole 'envs' na 'envs' s prístupom jadra na zápis (užívateľ nemá mať prístup k tomuto mapovaniu) a aby sa toto isté pole 'envs' mapovalo od adresy 'UENVS' pre používateľa iba na čítanie.
```c
void
mem_init(void)
{
...
	//////////////////////////////////////////////////////////////////////
	// Make 'envs' point to an array of size 'NENV' of 'struct Env'.
	// LAB 3: Your code here. line 184

	envs = (struct Env *) boot_alloc(NENV * sizeof(struct Env));
	memset(envs, 0, NENV * sizeof(struct Env));
...
	//////////////////////////////////////////////////////////////////////
	// Map the 'envs' array read-only by the user at linear address UENVS
	// (ie. perm = PTE_U | PTE_P).
	// Permissions:
	//    - the new image at UENVS  -- kernel R, user R
	//    - envs itself -- kernel RW, user NONE
	// LAB 3: Your code here. line 219
	psize = ROUNDUP(sizeof(struct Env) * NENV, PGSIZE);
	boot_map_region(kern_pgdir, UENVS, psize, PADDR(envs), (PTE_U |PTE_P));
...
}
```

### Úloha 2: Dokončite implementáciu nasledovných funkcií v súbore 'kern/env.c': 'env_init()', 'env_setup_vm()', 'region_alloc()', 'load_icode()', 'env_create()' a 'env_run()'.

### env_init()
### Cieľom funkcie je inicializovať všetky štruktúry 'Env' v poli 'envs' a pridať ich do zoznamu 'env_free_list'. Na konci funkcie sa volá 'env_init_percpu()', ktorá nastavuje segmentačný hardvér. Ten je potrebné nastaviť aj pre úroveň behu procesora 3 (user), doteraz je nastavený iba pre beh v ringu 0 (kernel).
### Dostatočne vážne berte komentár ku funkcii, v ktorom sa píše, že všetky položky zoznamu musia byť v tom istom poradí, ako sú v poli 'envs'. Z toho vyplýva, že ich do zoznamu musíte vkladať odzadu, od konca poľa 'envs'.
```c
void
env_init(void)
{
	// Set up envs array
	// LAB 3: Your code here.
	env_free_list = NULL;
	
	for(int i = NENV; i >= 0 ;i--){
		envs[i].env_status = ENV_FREE;
		envs[i].env_link = env_free_list;
		envs[i].env_id = 0;
		env_free_list = &envs[i];
	}
	// Per-CPU part of the initialization
	env_init_percpu();
}


static int
env_setup_vm(struct Env *e)
{
...
	// LAB 3: Your code here.
	e->env_pgdir = (pde_t*)page2kva(p);
	for(i = PDX(UTOP); i < NPDENTRIES; i++)
		e->env_pgdir[i] = kern_pgdir[i];
	
	p->pp_ref++;
...
}
```

### region_alloc()
### Až táto funkcia slúži na alokáciu fyzickej pamäte veľkosti 'len' pre potreby užívateľského prostredia. Táto fyzická pamäť sa má mapovať na virtuálnu adresu od adresy 'va'. Nesmiete modifikovať alokovanú pamäť RAM (t.j. nulovať ju pri alokácii). Pozor na správne nastavenie oprávnení! Všimnite si dôležité hinty, ktoré sa v jednotlivých funkciách (v komentároch) nachádzajú. Táto funkcia nemusí dostať adresu 'va', ktorá je zarovnaná na veľkosť stránky (t.j. deliteľná bezo zvyšku veľkosťou stránky). Podobne to platí aj pre samotnú veľkosť alokovanej oblasti, vstupný argument funkcie 'len'. Preto musíte hranice alokácie voliť opatrne: začiatok zaokrúhliť nadol na najbližší násobok veľkosti stránky a koniec nahor na najbližší násobok veľkosti stánky, t.j. mapovať región <ROUNDOWN(va); ROUNDUP(va+len))

```c
static void
region_alloc(struct Env *e, void *va, size_t len)
{
	// LAB 3: Your code here.
	// (But only if you need it for load_icode.)
	//
	// Hint: It is easier to use region_alloc if the caller can pass
	//   'va' and 'len' values that are not page-aligned.
	//   You should round va down, and round (va + len) up.
	//   (Watch out for corner-cases!)
	uintptr_t start = ROUNDDOWN((uintptr_t) va, PGSIZE),
	end = ROUNDUP((uintptr_t) va + len, PGSIZE);

	int perms = PTE_P | PTE_U | PTE_W;

	for (; start < end; start += PGSIZE) {
		struct PageInfo *p = NULL;

		if (!(p = page_alloc(ALLOC_ZERO)))
			panic("region_alloc: page_alloc failed, out of memory.");

		if(page_insert(e->env_pgdir, p,(void *) start, perms))
				panic("region_alloc: page_insert failed, out of memory.");
	}
}
```
### load_icode()
### Kto by si chcel uľahčiť život, nech zmení obsah registra 'CR3' tak, aby mal život veselší, a potom sa algoritmus skráti asi na nasledovné položky:

### Pomocou funkcie 'region_alloc()' alokuj pamäť pre segment.
### Od adresy 'p_va' nakopíruj 'p_filesz' dát z binárky+'p_offset'.
### Od adresy 'p_va'+'p_filesz' vynuluj 'p_memsz'-'p_filesz' bajtov.

```c
static void
load_icode(struct Env *e, uint8_t *binary)
{
...
	// LAB 3: Your code here.
	struct Elf* elf = (struct Elf*) binary;

	if(elf->e_magic != ELF_MAGIC)
		panic("load_icode: Invalid ELF file.");

	struct Proghdr* ph = (struct Proghdr*) (binary + elf->e_phoff);
	struct Proghdr *eph = ph + elf->e_phnum;

	lcr3(PADDR(e->env_pgdir));

	for (; ph < eph; ++ph) {
		if(ph->p_type == ELF_PROG_LOAD) {
			region_alloc(e, (void*) ph->p_va, ph->p_memsz);

			memset((void*) ph->p_va, 0, ph->p_memsz);
			memcpy((void*) ph->p_va, binary + ph->p_offset, ph->p_filesz);
		}
	}

	e->env_tf.tf_eip = elf->e_entry;
	// Now map one page for the program's initial stack
	// at virtual address USTACKTOP - PGSIZE.

	// LAB 3: Your code here.
	region_alloc(e, (void*) USTACKTOP - PGSIZE, PGSIZE);
	lcr3(PADDR(kern_pgdir));
	e->env_tf.tf_eip = elf->e_entry;
}
```
### env_create()
### Alokujte nové prostredie pomocou volania funkcie 'env_alloc()' (rodičovské ID je 0) a pmocou'load_icode()' nahrajte programový kód prostredia. Na záver nastavte príslušný typ prostredia. V prípade nejakej chyby vyvolajte paniku.
```c
void
env_create(uint8_t *binary, enum EnvType type)
{
	// LAB 3: Your code here.
	struct Env *e = NULL;
	int result = env_alloc(&e, 0);

	if(result < 0)
		panic("env_create: %e.", result);

	load_icode(e, binary);
	e->env_type = type;
}
```
### env_run()
### Spustite užívateľské prostredie dané argumentom funkcie:
### Zmeňte stav prostredia 'curenv' (ak nejaké jestvuje), ak je jeho stav práve 'ENV_RUNNING', na stav 'ENV_RUNNABLE'. Ak ešte nebolo spustené žiadne prostredie (ideme spúšťať prvý krát užívateľské prostredie), premenná 'curenv' má hodnotu NULL.
### Nastav premennú 'curenv' na hodnotu práve spúšťaného prostredia.
### Zmeň stav spúšťaného prostredia na hodnotu 'ENV_RUNNING'.
### Zvýš počítadlo spustení práve spúšťaného prostredia.
### Prepni register 'CR3' (funkcia 'lcr3()') na pgdir spúšťaného prostredia.
### Vyvolaj funkciu 'env_pop_tf()', ktorá spôsobí zmenu kontextu, t.j. spustenie prostredia.
```c
void
env_run(struct Env *e)
{
...
	// LAB 3: Your code here.
	//panic("env_run not yet implemented");
	if(curenv && curenv->env_status == ENV_RUNNING)
		curenv->env_status = ENV_RUNNABLE;

	curenv = e;
	curenv->env_status = ENV_RUNNING;
	curenv->env_runs++;

	lcr3(PADDR(curenv->env_pgdir));
	env_pop_tf(&(curenv->env_tf));
}
```
### Úloha 3: V súbore 'kern/trap.c' upravte funkciu 'trap_dispatch()' tak, aby presmerovala spracovanie výnimky výpadku stránky na funkciu 'page_fault_handler()'.
```c
static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	switch (tf->tf_trapno) {
		case T_PGFLT:
			page_fault_handler(tf);
			return;
		case T_BRKPT:
			monitor(tf);
			return;
		case T_SYSCALL:
			tf->tf_regs.reg_eax = syscall(  tf->tf_regs.reg_eax,
											tf->tf_regs.reg_edx,
											tf->tf_regs.reg_ecx,
											tf->tf_regs.reg_ebx,
											tf->tf_regs.reg_edi,
											tf->tf_regs.reg_esi);
			return;
		default:
			break;
	}
...
}
```
### Úloha 4: Zmeňte funkciu 'trap_dispatch()' tak, aby prerušenie 3 vyvolalo monitor jadra.
-- Spravene v ulohe 3

### Úloha 5: Rozšírte funkciu 'trap_dispatch()' o spracovanie prerušenia systémového volania. Mali by ste v prípade systémového volania zavolať funkciu 'syscall()' (definovanú v súbore 'kern/syscall.c') s príslušnými argumentmi. Po vykonaní systémového volania by ste mali návratovú hodnotu vrátiť užívateľskému procesu cez register '%eax'. Doimplementujte funkciu 'syscall()' (zabezpečte, aby funkcia vracala '-E_INVAL', ak je neplatné číslo systémového volania!). Funkciu 'syscall()' rozšírte o možnosť volania všetkých doteraz definovaných služieb systému (viď 'inc/syscall.h').
```c
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.

	//panic("syscall not implemented");

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
		default:
			return -E_INVAL;
	}
}
```
### Úloha 6: V knižnici užívateľa inicializujte premennú 'thisenv' tak, aby ukazovala na správny prvok 'struct Env' poľa 'envs[]'.funkcia 'libmain()' v súbore 'lib/libmain.c'.
```c
void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	thisenv = envs + ENVX(sys_getenvid());
...
}
```

### Úloha 7: Zmeňte súbor 'kern/trap.c' tak, aby sa vyvolala funkcia 'panic()', ak nastane výpadok stránky v móde jadra. Pomôcka: na rozhodnutie, či nastal výpadok v móde jadra alebo používateľa, použite dva spodné bity registra 'CS' inštrukcie, ktorá spôsobila výpadok stránky (hodnota registra je uložená v položke 'tf_cs').
```c
void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	extern void TH_DIVIDE(); 	SETGATE(idt[T_DIVIDE], 0, GD_KT, TH_DIVIDE, 0); 
	extern void TH_DEBUG(); 	SETGATE(idt[T_DEBUG], 0, GD_KT, TH_DEBUG, 0); 
	extern void TH_NMI(); 		SETGATE(idt[T_NMI], 0, GD_KT, TH_NMI, 0); 
	extern void TH_BRKPT(); 	SETGATE(idt[T_BRKPT], 0, GD_KT, TH_BRKPT, 3); 
	extern void TH_OFLOW(); 	SETGATE(idt[T_OFLOW], 0, GD_KT, TH_OFLOW, 0); 
	extern void TH_BOUND(); 	SETGATE(idt[T_BOUND], 0, GD_KT, TH_BOUND, 0); 
	extern void TH_ILLOP(); 	SETGATE(idt[T_ILLOP], 0, GD_KT, TH_ILLOP, 0); 
	extern void TH_DEVICE(); 	SETGATE(idt[T_DEVICE], 0, GD_KT, TH_DEVICE, 0); 
	extern void TH_DBLFLT(); 	SETGATE(idt[T_DBLFLT], 0, GD_KT, TH_DBLFLT, 0); 
	extern void TH_TSS(); 		SETGATE(idt[T_TSS], 0, GD_KT, TH_TSS, 0); 
	extern void TH_SEGNP(); 	SETGATE(idt[T_SEGNP], 0, GD_KT, TH_SEGNP, 0); 
	extern void TH_STACK(); 	SETGATE(idt[T_STACK], 0, GD_KT, TH_STACK, 0); 
	extern void TH_GPFLT(); 	SETGATE(idt[T_GPFLT], 0, GD_KT, TH_GPFLT, 0); 
	extern void TH_PGFLT(); 	SETGATE(idt[T_PGFLT], 0, GD_KT, TH_PGFLT, 0); 
	extern void TH_FPERR(); 	SETGATE(idt[T_FPERR], 0, GD_KT, TH_FPERR, 0); 
	extern void TH_ALIGN(); 	SETGATE(idt[T_ALIGN], 0, GD_KT, TH_ALIGN, 0); 
	extern void TH_MCHK(); 		SETGATE(idt[T_MCHK], 0, GD_KT, TH_MCHK, 0); 
	extern void TH_SIMDERR(); 	SETGATE(idt[T_SIMDERR], 0, GD_KT, TH_SIMDERR, 0); 
	extern void TH_SYSCALL(); 	SETGATE(idt[T_SYSCALL], 0, GD_KT, TH_SYSCALL, 3); 

	// Per-CPU setup 
	trap_init_percpu();
}

void
page_fault_handler(struct Trapframe *tf)
{
...
	// LAB 3: Your code here.
	if (tf->tf_cs == GD_KT) {
		print_trapframe(tf);
		panic("kernel page fault va %08x\n", fault_va);
	}
...
}
```
### Úloha 8: Preštudujte si funkciu 'user_mem_assert()' v súbore 'kern/pmap.c' a podobným spôsobom implementujte funkciu 'user_mem_check()' v tom istom súbore.
```c
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
	// LAB 3: Your code here.
	uintptr_t start = (uintptr_t)ROUNDDOWN(va, PGSIZE),
				end = (uintptr_t)ROUNDUP(va + len, PGSIZE);

	perm = perm | PTE_P;
	pte_t *pt;
	// first check the page va in
	pt = pgdir_walk(env->env_pgdir, (void*) start, 0);
	if (!pt || (uintptr_t)va >= ULIM || !(PGOFF(*pt) & perm)) {
		// if fault, set the report addr to be va
		user_mem_check_addr = (uintptr_t)va;
		return -E_FAULT;
	}

	for (; start < end; start += PGSIZE) {
		pte_t *page_table_entry = pgdir_walk(env->env_pgdir, (void *) start, 0);

		if(!page_table_entry || start >= ULIM || (((*page_table_entry) & perm) != perm)) {
			user_mem_check_addr = start;
			return -E_FAULT;
		}
	}
	return 0;
}
```
### Úloha 9: Zmeňte súbor 'kern/syscall.c' tak, aby kontroloval argumenty systémových volaní.
--spravene v ulohe 5
```c
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
	user_mem_assert(curenv, s, len, PTE_U); 
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}
```
### Úloha 10: Na záver zmeňte funkciu 'debuginfo_eip()' v súbore 'kern/kdebug.c' tak, aby sa volala funkcia 'user_mem_check()' pre 'usd', 'stabs' a 'stabstr'
```c
int
debuginfo_eip(uintptr_t addr, struct Eipdebuginfo *info)
{
...

		// Make sure this memory is valid.
		// Return -1 if it is not.  Hint: Call user_mem_check.
		// LAB 3: Your code here.
		if(user_mem_check(curenv, usd, sizeof(usd), PTE_U) != 0)
			return -1;

		stabs = usd->stabs;
		stab_end = usd->stab_end;
		stabstr = usd->stabstr;
		stabstr_end = usd->stabstr_end;

		// Make sure the STABS and string table memory is valid.
		// LAB 3: Your code here.
		if(user_mem_check(curenv, stabs, sizeof(struct Stab), PTE_U) != 0)
			return -1;

		if(user_mem_check(curenv, stabstr, stabstr_end - stabstr, PTE_U) != 0)
			return -1;
...
}
```

divzero: OK (1.5s) 

softint: OK (1.0s) 

badsegment: OK (1.0s) 

Part A score: 30/30

faultread: OK (1.0s) 

faultreadkernel: OK (2.0s) 

faultwrite: OK (1.0s) 

faultwritekernel: OK (1.9s) 

breakpoint: OK (2.1s) 

testbss: OK (1.0s) 

hello: OK (2.0s) 

buggyhello: OK (2.0s) 

buggyhello2: OK (2.0s) 

evilhello: OK (1.9s) 

Part B score: 50/50

### Score: 80/80
