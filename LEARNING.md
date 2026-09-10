# Learning log

One entry per build day. The rule is simple: write down the thing I understood that day that I did not understand the day before. If nothing goes in, nothing was learned, and that is worth knowing too.

---

## 28 August 2026

Built the first working version of the control point: `agent.py`, `tools.py`, `gateway.py` and four Cedar policies, then `sandbox_tools.py` in the evening. Mock mode ran end to end and put five decisions on the record, two permitted and three refused.

The denial I did not expect was the harmless one. `print(2 + 2)` was refused. Not because the code was dangerous, but because the call arrived with `sandboxed: false`, and no policy permits code execution outside a boundary. The gateway was not judging the code at all. It was judging whether the containment that would make the code survivable was actually in place.

That is the whole argument of the essay, and it fell out of writing one Cedar rule rather than out of writing an argument. A permission conditional on the boundary being real at the moment of the call is a different object from a smaller permission, and I could not have shown that difference in prose.

---
