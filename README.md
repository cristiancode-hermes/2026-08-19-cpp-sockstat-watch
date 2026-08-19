# sockstat-watch

Monitor de estadísticas de sockets de Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/sockstat` y `/proc/net/sockstat6` para mostrar sockets en uso,
TIME_WAIT, orphans TCP, memoria de sockets y presión de puertos efímeros.

## Features

- **Sockets globales**: contador `sockets: used` del kernel
- **Por protocolo**: TCP/UDP/RAW/FRAG (+ variantes IPv6) con `inuse`, `orphan`, `tw`, `alloc`, `mem`
- **TIME_WAIT pressure**: barra ASCII relativa a soft-limit 2000 (alerta de agotamiento de puertos)
- **Watch mode**: refresco periódico con deltas (`+N` / `-N`) entre snapshots
- **JSON output**: snapshot completo para pipelines
- **Demo mode**: carga sintética alta (útil sin `/proc` o para capturas)
- **Selftest**: parser + demo + JSON + lectura real de `/proc`
- **--no-color**: paleta ANSI mutable (sin códigos en pipes)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o sockstat-watch
```

## Usage

```bash
# Snapshot único
./sockstat-watch

# Modo watch (cada 2s)
./sockstat-watch --watch 2

# JSON
./sockstat-watch --json

# Demo (carga sintética)
./sockstat-watch --demo

# Sin colores
./sockstat-watch --no-color

# Auto-tests
./sockstat-watch --selftest
```

## Data Source

| Archivo | Campos |
|---------|--------|
| `/proc/net/sockstat` | `sockets used`, `TCP` (inuse/orphan/tw/alloc/mem), `UDP`, `UDPLITE`, `RAW`, `FRAG` |
| `/proc/net/sockstat6` | `TCP6`, `UDP6`, `UDPLITE6`, `RAW6`, `FRAG6` |

- `mem` se reporta en **páginas del kernel** (típicamente 4 KiB) y se convierte a KiB/MiB/GiB.
- `tw` (TIME_WAIT) alto bajo tráfico corto-vivido puede agotar el rango de puertos efímeros.
- `orphan` son sockets TCP sin dueño de proceso (posible leak / cierre abrupto).

## Example Output

```
+================================================+
|     Linux Socket Statistics Monitor            |
+================================================+
  Source: /proc/net/sockstat + sockstat6

  -- Aggregate --
  Sockets used:  842
  Proto inuse:   301
  TIME_WAIT:     1550
  Orphans:       2
  Sock mem:      632.0 KiB (158 pages)
  TW pressure:   ||||||||||||||||.... (77% of soft limit 2000)

  -- Protocols --
  Proto      inuse   orphan       tw    alloc       mem
  ----------------------------------------------------------
  TCP          186        2     1240      412        98
  UDP           14        -        -        -        12
  ...
  TCP6          94        0      310      180        44
```

## License

MIT
