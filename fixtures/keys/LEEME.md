# Claves de PRUEBA — no usar para nada real

`test_seed.hex` y `other_seed.hex` son semillas Ed25519 privadas, publicadas a
propósito en el repo para que los tests sean reproducibles. Cualquiera puede
firmar con ellas. En producción la semilla vive fuera del repo, y la clave
pública de confianza se fija en la configuración del cargador.
