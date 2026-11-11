# SafeNet

App Android (Kotlin) de uso personal que filtra sitios para adultos a nivel de red,
con un interruptor protegido por clave.

## Cómo funciona
- VPN local (VpnService): intercepta solo las consultas DNS, sin enviar tráfico a servidores propios.
- Lista de ~950.000 dominios bloqueados + SafeSearch forzado en Google, Bing y DuckDuckGo.
- DNS filtrado (1.1.1.3 / 1.0.0.3) como segunda capa y bloqueo de DNS cifrado alterno (DoH/DoT).
- Clave de 15+ caracteres guardada solo como hash (PBKDF2, 200.000 iteraciones, sal aleatoria).
- 5 intentos fallidos = 24 horas sin poder apagar la protección (resistente a cambios de hora).

## Tecnologías
Kotlin, Android SDK, VpnService, PBKDF2, SharedPreferences.

## Capturas
<img width="2720" height="2480" alt="safenet_interfaz_activado" src="https://github.com/user-attachments/assets/d0e91699-36b9-4769-bb97-528f2bffc5f8" />
<img width="2720" height="1760" alt="safenet_sistema_activado" src="https://github.com/user-attachments/assets/73fd6ea7-5095-4e81-a602-a69c041b6d99" />


## Créditos
Listas de dominios: StevenBlack/hosts y blocklistproject/Lists (licencia MIT).
