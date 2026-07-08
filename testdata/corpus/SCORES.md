# Decompiler Corpus Scores

Recorded 2026-07-08. Higher is better for funcs/calls/structured/rich types; **lower** is better
for raw gotos and elided logic. These are the acceptance ruler for v0.9.0 — regenerate
with `CORPUS_UPDATE=1 go test ./internal/corpus`.

Proxies (Task 1): funcs/calls = manifest names recovered; raw gotos = unstructured jumps;
elided logic = real logic emitted as comments; structured = real if/for/switch; rich types
= any non-int64 type recovered. Human-readability scoring is added with the readable emitter.

| Program | Funcs | Calls | Raw gotos | Elided logic | Structured | Rich types |
|---------|-------|-------|-----------|--------------|------------|------------|
| controlflow | 3/3 | 0/3 | 2 | 19 | 6 | false |
| structs | 3/3 | 0/2 | 2 | 9 | 4 | false |
| slicesmaps | 2/2 | 0/2 | 3 | 25 | 8 | false |
| goroutines | 1/1 | 0/1 | 4 | 43 | 11 | false |
| interfaces | 3/3 | 0/2 | 5 | 40 | 13 | false |
| deferpanic | 1/1 | 0/1 | 3 | 19 | 7 | false |
| **total** | **13/13** | **0/11** | **19** | **155** | **49** | **0/6** |

