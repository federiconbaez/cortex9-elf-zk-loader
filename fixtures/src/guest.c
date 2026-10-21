/* Invitado mínimo para el cargador FNBR: sin libc, ET_EXEC estático.
 * fnbr_entry suma los bytes de "FNBR" (70+78+66+82 = 296) leyendo .rodata
 * y escribe en .data, para ejercitar segmentos R-X, R y RW. */
static const char msg[] = "FNBR";
static long counter = 1000;

long fnbr_entry(void)
{
    long s = 0;
    for (int i = 0; i < 4; i++)
        s += msg[i];
    counter += s;           /* toca .data (RW) */
    return counter - 1000;  /* 296 */
}
