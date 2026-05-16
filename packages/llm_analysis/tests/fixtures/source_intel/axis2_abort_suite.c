/*
 * axis2_abort_suite.c — axis-2 verdict coverage fixture.
 *
 * One function per abort-class macro/call. Each is a memory-corruption
 * shape (cpp/null-dereference) gated by an abort that runs before
 * the deref, so axis-2 abort-dominance must emit NOT_EXPLOITABLE.
 *
 * Macros covered: panic, abort, _Exit, __builtin_trap, assert.
 * (BUG_ON is covered by the existing fp_bug_on_dominates.c fixture.)
 *
 * Plus a cross-function negative — abort exists in a sibling
 * function, NOT in the finding's enclosing function.
 */

#include <stddef.h>

extern void panic(const char *msg);
extern void abort(void);
extern void _Exit(int);
extern void assert(int);


/* 1. panic dominance */
void op_with_panic(int *p)
{
	if (!p)
		panic("p was NULL");
	*p = 1;
}


/* 2. abort dominance */
void op_with_abort(int *p)
{
	if (!p)
		abort();
	*p = 1;
}


/* 3. _Exit dominance */
void op_with_exit(int *p)
{
	if (!p)
		_Exit(1);
	*p = 1;
}


/* 4. __builtin_trap dominance */
void op_with_trap(int *p)
{
	if (!p)
		__builtin_trap();
	*p = 1;
}


/* 5. assert dominance */
void op_with_assert(int *p)
{
	assert(p);
	*p = 1;
}


/* 6. cross-function negative — abort in SIBLING, not finding's
 *    enclosing function. Must NOT suppress. Note: include a caller
 *    of op_no_abort so dead-code doesn't fire either. */
void sibling_op_with_abort(int *p)
{
	if (!p)
		abort();
}

void op_no_abort(int *p)
{
	*p = 1;
}

int main(void)
{
	int x = 0;
	op_no_abort(&x);
	return 0;
}
