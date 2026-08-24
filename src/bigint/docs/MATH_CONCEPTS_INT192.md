# Mathematical Foundations of 192-Bit Signed Integer Arithmetic (`I192`)

## 1. Radix $2^{64}$ Multi-Precision Representation

### 1.1 Positional Numeral Systems in Base $B = 2^{64}$
A standard 64-bit CPU cannot natively represent a 192-bit scalar integer in a single register. We represent large numbers using a **positional base $B$ numeral system** (also called *multi-limb representation*), where the radix is chosen to match the largest native word size used for individual limb storage:

$$B = 2^{64}$$

Any 192-bit integer $X$ is partitioned into three 64-bit "limbs":
- **Low Limb ($X\_{\text{lo}}$):** The least significant 64 bits, having weight $B^0 = 2^0 = 1$.
- **Middle Limb ($X\_{\text{mid}}$):** The middle 64 bits, having weight $B^1 = 2^{64}$.
- **High Limb ($X\_{\text{hi}}$):** The most significant 64 bits, having weight $B^2 = 2^{128}$.

$$X = X\_{\text{hi}} \cdot 2^{128} + X\_{\text{mid}} \cdot 2^{64} + X\_{\text{lo}}$$

```
┌────────────────────┬────────────────────┬────────────────────┐
│  High Limb (hi)     │  Middle Limb (mid)  │  Low Limb (lo)     │
│  64 bits            │  64 bits            │  64 bits           │
│  Bits [191 .. 128]  │  Bits [127 .. 64]   │  Bits [63 .. 0]    │
│  Weight: 2¹²⁸        │  Weight: 2⁶⁴        │  Weight: 2⁰        │
│  Carries the Sign Bit│  Pure Unsigned Mag. │  Pure Unsigned Mag.│
└────────────────────┴────────────────────┴────────────────────┘
◄─────────────────────────── Total: 192 Bits ──────────────────►
```

### 1.2 The Limb Role Asymmetry
Although in Rust all three limbs are stored inside `i64` fields for struct symmetry (`I192(pub [i64; 3])`), their mathematical roles are asymmetric:
1. **$X\_{\text{lo}}$ and $X\_{\text{mid}}$ are strictly unsigned magnitudes:**
   $$X\_{\text{lo}}, X\_{\text{mid}} \in [0, 2^{64} - 1]$$
   During arithmetic (addition, subtraction, multiplication), both are cast to `u64`. They represent pure numerical value modulo $2^{64}$, with no independent sign of their own.
2. **$X\_{\text{hi}}$ carries the sign bit:**
   $$X\_{\text{hi}} \in [-2^{63}, 2^{63} - 1]$$
   Bit 63 of $X\_{\text{hi}}$ is bit 191 of the overall `I192` integer, dictating the sign of the whole value in two's complement representation.

---

## 2. The Two's Complement Ring $\mathbb{Z} / 2^{192}\mathbb{Z}$

### 2.1 Formal Two's Complement Mapping
The type `I192` is an element of the quotient ring $\mathbb{Z} / 2^{192}\mathbb{Z}$. A 192-bit sequence $(b\_{191}, b\_{190}, \dots, b\_1, b\_0) \in \lbrace 0, 1 \rbrace^{192}$ maps to a signed integer via:

$$V(X) = -b\_{191} \cdot 2^{191} + \sum\_{i=0}^{190} b\_i \cdot 2^i$$

The domain of representable values is:

$$X \in [-2^{191}, \; 2^{191} - 1]$$

- **Representable minimum:** $-2^{191} = -3138550867693340381917894711603833208051177722232017256448$
- **Representable maximum:** $+2^{191} - 1 = +3138550867693340381917894711603833208051177722232017256447$

`I192` does not expose named `MAX`/`MIN` constants in code (only `ZERO`, `ONE`, `MINUS_ONE`); the bounds above are the mathematical range the three-limb representation can hold, achieved with `I192::new(i64::MIN, 0, 0)` and `I192::new(i64::MAX, -1, -1)` respectively.

### 2.2 Constant Identities and Limb Values

| Constant Identity | High Limb (`hi`) | Mid Limb (`mid`) | Low Limb (`lo`) | Mathematical Value |
| :--- | :--- | :--- | :--- | :--- |
| `I192::ZERO` | `0` | `0` | `0` | $0$ (Additive Identity) |
| `I192::ONE` | `0` | `0` | `1` | $+1$ (Multiplicative Identity) |
| `I192::MINUS_ONE` | `-1` | `-1` | `-1` | $-1 \equiv 2^{192}-1 \pmod{2^{192}}$ |
| Representable max (`new(i64::MAX, -1, -1)`) | `i64::MAX` | `-1` | `-1` | $+2^{191}-1$ |
| Representable min (`new(i64::MIN, 0, 0)`) | `i64::MIN` | `0` | `0` | $-2^{191}$ |

#### Why `MINUS_ONE` is `new(-1, -1, -1)`:
In two's complement, $-1 \pmod{2^{192}} = 2^{192} - 1 = \sum\_{i=0}^{191} 2^i$, which consists of 192 ones (`0xFF...FF`).
- Low 64 bits: `0xFFFFFFFFFFFFFFFF` = `u64::MAX` = `-1 as i64`.
- Mid 64 bits: `0xFFFFFFFFFFFFFFFF` = `u64::MAX` = `-1 as i64`.
- High 64 bits: `0xFFFFFFFFFFFFFFFF` = `u64::MAX` = `-1 as i64`.

---

## 3. Bitwise Negation (`std::ops::Neg`) & Carry Propagation

### 3.1 Mathematical Definition
Two's complement negation is algebraically defined as bitwise inversion plus 1:

$$-X = (\sim X) + 1 \pmod{2^{192}}$$

Where $\sim X$ is the bitwise NOT operation ($\sim X = (2^{192} - 1) - X$).

### 3.2 Three-Stage Limb Evaluation
Breaking $X = (X\_{\text{hi}} \cdot 2^{128} + X\_{\text{mid}} \cdot 2^{64} + X\_{\text{lo}})$ into limbs:

$$\sim X = (\sim X\_{\text{hi}}) \cdot 2^{128} + (\sim X\_{\text{mid}}) \cdot 2^{64} + (\sim X\_{\text{lo}})$$

Adding 1 only affects the lowest limb directly; any overflow it produces must ripple upward through **two** carry stages, not one, since there are three limbs instead of I256's two:

1. **Low Limb Calculation (fixed `+1` addend):**
   $$\text{lo} = (\sim X\_{\text{lo}} + 1) \bmod 2^{64}, \qquad c\_1 = 1 \text{ iff } \sim X\_{\text{lo}} + 1 = 2^{64} \text{ (equivalently, } X\_{\text{lo}} = 0\text{)}$$

2. **Middle Limb Calculation (variable carry-in $c\_1 \in \lbrace 0, 1 \rbrace$):**
   $$\text{mid} = (\sim X\_{\text{mid}} + c\_1) \bmod 2^{64}, \qquad c\_2 = 1 \text{ iff } \sim X\_{\text{mid}} + c\_1 \ge 2^{64}$$

3. **High Limb Calculation (variable carry-in $c\_2 \in \lbrace 0, 1 \rbrace$):**
   $$\text{hi} = (\sim X\_{\text{hi}} + c\_2) \bmod 2^{64}$$

```
X:            [      X_hi      ]  [     X_mid      ]  [      X_lo      ]
                       │                    │                   │
Bitwise NOT:  [     ~X_hi      ]  [    ~X_mid      ]  [     ~X_lo      ]
                                                                 │ + 1
                                                      [ lo = (~X_lo + 1) mod 2⁶⁴ ]
                       │                    │                   │
Carry c1:              │                    └──◄── overflow? ───┘
                       │           [ mid = (~X_mid + c1) mod 2⁶⁴ ]
Carry c2:              └──◄──────────── overflow? ───────────────┘
              [ hi = (~X_hi + c2) mod 2⁶⁴ ]
```

### 3.3 Theorem: The `result == 0` Heuristic Is Valid *Only* for a Fixed `+1` Addend
> **Theorem (boundary limb):** For any unsigned 64-bit integer $X\_{\text{lo}} \in [0, 2^{64}-1]$,
> $$(\sim X\_{\text{lo}} + 1) \equiv 0 \pmod{2^{64}} \iff X\_{\text{lo}} = 0$$

*Proof:*
- Bitwise inversion is $\sim X\_{\text{lo}} = (2^{64} - 1) - X\_{\text{lo}}$.
- Adding 1: $(\sim X\_{\text{lo}}) + 1 = 2^{64} - X\_{\text{lo}}$.
- For this quantity to equal $2^{64}$ (i.e. $0 \bmod 2^{64}$), we require $2^{64} - X\_{\text{lo}} = 2^{64} \implies X\_{\text{lo}} = 0$.
- For all other values $X\_{\text{lo}} \in [1, 2^{64}-1]$, the result is strictly in $[1, 2^{64}-1]$, hence $\text{lo} \neq 0$ and carry is $0$. $\blacksquare$

This theorem is exactly why I256's two-limb negation (see `MATH_CONCEPTS_INT256.md` §3.3) can safely test `lo == 0` to decide the single carry into `hi`: I256's only addition step is the fixed `+1`, so "result is zero" and "an overflow occurred" are logically equivalent.

**`I192` has an intermediate limb, and the equivalence breaks there.** The middle-limb addition in stage 2 is $\sim X\_{\text{mid}} + c\_1$, where $c\_1 \in \lbrace 0, 1 \rbrace$ is *itself variable*, not a fixed constant. This invalidates the naive heuristic:

> **Counter-example:** Let $X\_{\text{mid}} = -1$ (i.e. `u64::MAX`) and suppose $c\_1 = 0$ (no carry arrived from the low limb, which happens whenever $X\_{\text{lo}} \neq 0$). Then:
> $$\sim X\_{\text{mid}} + c\_1 = 0 + 0 = 0$$
> The result is zero, **but no overflow occurred** — $c\_2$ must be $0$, since adding $0$ to a value already less than $2^{64}$ can never overflow. A check of the form "`mid == 0` implies carry" would wrongly conclude $c\_2 = 1$ and inject a phantom carry into `hi`.

This is not a hypothetical: it is precisely the bug that shipped in an earlier revision of this file, where the middle- and high-limb carries were derived from `(lo == 0)` / `(mid == 0)` instead of the genuine overflow flag. It was caught by differential (oracle) testing against Python's arbitrary-precision arithmetic across randomized and boundary-value 192-bit operands — see §3.5 for the concrete failing case. The fix is to track the *real* carry bit returned by `overflowing_add` at every stage, since that flag is structurally correct regardless of whether the addend is a fixed constant or a variable carry-in:

```rust
let (lo, c1) = (!self.lo() as u64).overflowing_add(1);
let (mid, c2) = (!self.mid() as u64).overflowing_add(c1 as u64);
let hi = (!self.hi() as u64).wrapping_add(c2 as u64);
```

### 3.4 Edge Case: $-(-2^{191}) = -2^{191}$
For $X = \text{MIN} = -2^{191}$ (`hi = i64::MIN`, `mid = 0`, `lo = 0`):
1. $\text{lo} = (\mathord{\sim}0 + 1) = 0$, producing carry $c\_1 = 1$ (since $X\_{\text{lo}} = 0$).
2. $\text{mid} = (\mathord{\sim}0 + 1) = 0$, producing carry $c\_2 = 1$ (since $\sim X\_{\text{mid}} + c\_1 = (2^{64}-1) + 1 = 2^{64}$, which overflows).
3. $\text{hi} = (\mathord{\sim}\text{i64::MIN}) + 1 = \text{0x7FFF...FFFF} + 1 = \text{0x8000...0000} = \text{i64::MIN}$.
4. Result is `I192::new(i64::MIN, 0, 0) == I192::MIN`.

This correctly mirrors the two's complement asymmetric range where $-\text{MIN} = \text{MIN}$ due to modular wrap-around, and both carry stages fire "for real" reasons (each addition genuinely overflows), so this edge case does not exercise the §3.3 pitfall.

### 3.5 Edge Case: $-(-1) = 1$, the Case That Exposed the Bug
For $X = \text{MINUS}\_{\text{ONE}} = (-1, -1, -1)$ (`hi = mid = lo = -1`, i.e. all limbs are `u64::MAX`):
1. $\text{lo} = (\mathord{\sim}(\text{u64::MAX}) + 1) = (0 + 1) = 1$. Since $\text{lo} \neq 0$, $c\_1 = 0$ — correctly, no carry, because $X\_{\text{lo}} \neq 0$.
2. $\text{mid} = (\mathord{\sim}(\text{u64::MAX}) + c\_1) = (0 + 0) = 0$. The **correct** carry is $c\_2 = 0$: no overflow occurred, we simply added $0$ to $0$.
   - The buggy `(mid == 0)` heuristic would instead set $c\_2 = 1$ here, since it cannot distinguish "the sum is naturally zero" from "the sum overflowed to zero".
3. $\text{hi} = (\mathord{\sim}(\text{u64::MAX}) + c\_2) = (0 + 0) = 0$ with the correct carry chain, versus $(0 + 1) = 1$ with the buggy one.
- **Correct result:** `I192::new(0, 0, 1) == I192::ONE`. ✓
- **Buggy result (pre-fix):** `I192::new(1, 0, 1)`, off by $2^{128}$. ✗

---

## 4. Multi-Limb Addition (`std::ops::Add`) with Carry

### 4.1 Algebraic Formulation
Let $A = A\_{\text{hi}} \cdot 2^{128} + A\_{\text{mid}} \cdot 2^{64} + A\_{\text{lo}}$ and $B = B\_{\text{hi}} \cdot 2^{128} + B\_{\text{mid}} \cdot 2^{64} + B\_{\text{lo}}$. The sum is:

$$A + B = (A\_{\text{hi}} + B\_{\text{hi}}) \cdot 2^{128} + (A\_{\text{mid}} + B\_{\text{mid}}) \cdot 2^{64} + (A\_{\text{lo}} + B\_{\text{lo}})$$

This is a standard **ripple-carry** addition across three limbs. Unlike negation's carry chain (§3), every carry here comes from adding two *genuinely independent* operands at each stage, so each stage's overflow flag can be read directly off `overflowing_add` without the ambiguity discussed in §3.3:

1. **Low Limb:**
   $$A\_{\text{lo}} + B\_{\text{lo}} = c\_1 \cdot 2^{64} + \text{lo}, \qquad c\_1 = \lfloor (A\_{\text{lo}} + B\_{\text{lo}}) / 2^{64} \rfloor \in \lbrace 0, 1 \rbrace$$

2. **Middle Limb**, receiving carry $c\_1$ from the low limb:
   $$A\_{\text{mid}} + B\_{\text{mid}} + c\_1 = c\_2 \cdot 2^{64} + \text{mid}, \qquad c\_2 \in \lbrace 0, 1 \rbrace$$

   The implementation computes this in two `overflowing_add` steps — $(A\_{\text{mid}} + B\_{\text{mid}})$ with carry-out $c\_2^{(a)}$, then $(\cdot + c\_1)$ with carry-out $c\_2^{(b)}$ — and sums the two carry-out bits: $c\_2 = c\_2^{(a)} + c\_2^{(b)}$. Because $A\_{\text{mid}}, B\_{\text{mid}} \le 2^{64}-1$, their sum is at most $2^{65}-2$, so $c\_2^{(a)}$ and $c\_2^{(b)}$ can never both be $1$ simultaneously — $c\_2$ is always a clean single bit.

3. **High Limb**, receiving carry $c\_2$ from the middle limb:
   $$\text{hi} = (A\_{\text{hi}} + B\_{\text{hi}} + c\_2) \bmod 2^{64}$$

```
        A_hi                A_mid               A_lo
+       B_hi                B_mid               B_lo
──────────────────────────────────────────────────────────────────────
  (A_hi+B_hi+c2)      (A_mid+B_mid+c1) mod 2⁶⁴    (A_lo+B_lo) mod 2⁶⁴
          ▲                    │  ▲                      │
          └──── Carry c2 ──────┘  └────── Carry c1 ───────┘
```

### 4.2 Step-by-Step Numerical Example
Consider adding $A = (10 \cdot 2^{128} + 5 \cdot 2^{64} + (2^{64}-1))$ and $B = (5 \cdot 2^{128} + 2 \cdot 2^{64} + 1)$:
- In code: `A = I192::new(10, 5, -1)`, `B = I192::new(5, 2, 1)`.
- Low addition: $(2^{64}-1) + 1 = 2^{64} = 1 \cdot 2^{64} + 0$.
  - `lo = 0`, `c1 = 1`
- Middle addition: $5 + 2 + 1 = 8$, no overflow.
  - `mid = 8`, `c2 = 0`
- High addition: $10 + 5 + 0 = 15$.
- **Result:** $C = \text{I192::new}(15, 8, 0)$. This matches `test_add_with_carry` in the unit test suite.

---

## 5. Multi-Limb Subtraction (`std::ops::Sub`) with Borrow

### 5.1 Algebraic Formulation
Let $A = A\_{\text{hi}} \cdot 2^{128} + A\_{\text{mid}} \cdot 2^{64} + A\_{\text{lo}}$ and $B = B\_{\text{hi}} \cdot 2^{128} + B\_{\text{mid}} \cdot 2^{64} + B\_{\text{lo}}$. The difference is:

$$A - B = (A\_{\text{hi}} - B\_{\text{hi}}) \cdot 2^{128} + (A\_{\text{mid}} - B\_{\text{mid}}) \cdot 2^{64} + (A\_{\text{lo}} - B\_{\text{lo}})$$

Borrows ripple upward the same way carries do in §4, mirrored for subtraction:

1. **Low Limb:**
   $$b\_1 = 1 \text{ if } A\_{\text{lo}} \lt B\_{\text{lo}}, \text{ else } 0, \qquad \text{lo} = (A\_{\text{lo}} - B\_{\text{lo}} + b\_1 \cdot 2^{64}) \bmod 2^{64}$$

2. **Middle Limb**, absorbing borrow $b\_1$ from the low limb:
   $$b\_2 = 1 \text{ if } A\_{\text{mid}} - B\_{\text{mid}} - b\_1 \lt 0, \text{ else } 0, \qquad \text{mid} = (A\_{\text{mid}} - B\_{\text{mid}} - b\_1) \bmod 2^{64}$$

   As with addition, the implementation derives $b\_2$ from two `overflowing_sub` steps and sums their two borrow-out bits; since $A\_{\text{mid}}, B\_{\text{mid}} \in [0, 2^{64}-1]$, the two borrow-out bits can never both be $1$, so $b\_2$ is always a clean single bit.

3. **High Limb**, absorbing borrow $b\_2$ from the middle limb:
   $$\text{hi} = (A\_{\text{hi}} - B\_{\text{hi}} - b\_2) \bmod 2^{64}$$

```
        A_hi                A_mid               A_lo
-       B_hi                B_mid               B_lo
──────────────────────────────────────────────────────────────────────
  (A_hi-B_hi-b2)      (A_mid-B_mid-b1) mod 2⁶⁴    (A_lo-B_lo) mod 2⁶⁴
          ▲                    │  ▲                      │
          └──── Borrow b2 ─────┘  └────── Borrow b1 ──────┘
```

### 5.2 Step-by-Step Numerical Example
Consider subtracting $B = (10 \cdot 2^{128} + 5 \cdot 2^{64} + 1)$ from $A = (20 \cdot 2^{128} + 10 \cdot 2^{64} + 0)$:
- In code: `A = I192::new(20, 10, 0)`, `B = I192::new(10, 5, 1)`.
- Low subtraction: $A\_{\text{lo}} - B\_{\text{lo}} = 0 - 1 = -1 \equiv 2^{64}-1 \pmod{2^{64}}$.
  - `lo = -1 as i64` (`0xFFFFFFFFFFFFFFFF`), `b1 = 1`
- Middle subtraction: $10 - 5 - 1 = 4$, no further borrow needed.
  - `mid = 4`, `b2 = 0`
- High subtraction: $20 - 10 - 0 = 10$.
- **Result:** $C = \text{I192::new}(10, 4, -1)$. This matches `test_sub_with_borrow` in the unit test suite.

---

## 6. Full 192-Bit Multiplication (`std::ops::Mul`) Modulo $2^{192}$

### 6.1 The 384-Bit Product Expansion
Let two 192-bit integers be $X = a\_1 \cdot 2^{128} + b\_1 \cdot 2^{64} + c\_1$ and $Y = a\_2 \cdot 2^{128} + b\_2 \cdot 2^{64} + c\_2$, where $a\_1 = X\_{\text{hi}}, b\_1 = X\_{\text{mid}}, c\_1 = X\_{\text{lo}}$ and likewise for $Y$. Expanding the algebraic product yields nine partial terms, grouped here by weight:

$$X \cdot Y = \underbrace{a\_1 a\_2}\_{\text{Weight } 2^{256}} + \underbrace{(a\_1 b\_2 + b\_1 a\_2)}\_{\text{Weight } 2^{192}} + \underbrace{(a\_1 c\_2 + b\_1 b\_2 + c\_1 a\_2)}\_{\text{Weight } 2^{128}} + \underbrace{(b\_1 c\_2 + c\_1 b\_2)}\_{\text{Weight } 2^{64}} + \underbrace{c\_1 c\_2}\_{\text{Weight } 2^0}$$

(Each weight group above — $2^{256}$, $2^{192}$, $2^{128}$, $2^{64}$ — is implicitly multiplied by that power of two.)

```
                 a1 (hi)          b1 (mid)         c1 (lo)
×                a2 (hi)          b2 (mid)         c2 (lo)
──────────────────────────────────────────────────────────────────
                                                    c1·c2      (Weight 2⁰   -> [0..127])
                                   c1·b2                       (Weight 2⁶⁴  -> [64..191])
                                   b1·c2                       (Weight 2⁶⁴  -> [64..191])
                  a1·c2                                        (Weight 2¹²⁸ -> [128..255])
                  b1·b2                                        (Weight 2¹²⁸ -> [128..255])
                  c1·a2                                        (Weight 2¹²⁸ -> [128..255])
+ a1·b2                                                         (Weight 2¹⁹² -> [192..319])
+ b1·a2                                                         (Weight 2¹⁹² -> [192..319])
+ a1·a2                                                          (Weight 2²⁵⁶ -> [256..383])
──────────────────────────────────────────────────────────────────
  [ DISCARD >= 2¹⁹² ] │ [ UPPER 64 (hi) ] │ [ MIDDLE 64 (mid) ] │ [ LOWER 64 (lo) ]
```

### 6.2 Modulo $2^{192}$ Truncation Strategy
Because the output ring is $\mathbb{Z} / 2^{192}\mathbb{Z}$, any term with weight $\ge 2^{192}$ vanishes identically:

1. **Terms $a\_1 a\_2 \cdot 2^{256}$ and $(a\_1 b\_2 + b\_1 a\_2) \cdot 2^{192}$:**
   $$a\_1 a\_2 \cdot 2^{256} \equiv 0, \qquad (a\_1 b\_2 + b\_1 a\_2) \cdot 2^{192} \equiv 0 \pmod{2^{192}}$$
   *Optimization:* We never compute $a\_1 \cdot a\_2$, $a\_1 \cdot b\_2$, or $b\_1 \cdot a\_2$ at all — the code has no reference to them.

2. **Weight-$2^{128}$ Terms $a\_1 c\_2$, $b\_1 b\_2$, $c\_1 a\_2$:** Each is a 64-bit $\times$ 64-bit product landing at base offset $128$, so it spans bits $[128, 255]$. Only bits $[128, 191]$ — i.e. the *low 64 bits* of each product — actually fall inside the 192-bit window; the product's own upper 64 bits land at $[192, 255]$ and are discarded:
   $$p \cdot 2^{128} = \big(p\_{\text{hi}} \cdot 2^{64} + p\_{\text{lo}}\big) \cdot 2^{128} = p\_{\text{hi}} \cdot 2^{192} + p\_{\text{lo}} \cdot 2^{128} \equiv p\_{\text{lo}} \cdot 2^{128} \pmod{2^{192}}$$
   *Optimization:* Only the lower 64 bits of each of these three products are computed and kept; the code explicitly discards the upper half with `let (_, p3_lo) = mul_u64(c1, a2)`.

3. **Weight-$2^{64}$ Terms $b\_1 c\_2$ and $c\_1 b\_2$:** Each spans bits $[64, 191]$ — entirely inside the 192-bit window (worst case $(2^{64}-1)^2 \approx 2^{128}$, which at weight $2^{64}$ reaches at most bit $191$). Both the high and low halves of each product are kept in full.

4. **Lowest Term $c\_1 c\_2$ (Weight $2^0$):**
   $$c\_1 \cdot c\_2 = p\_{0,\text{hi}} \cdot 2^{64} + p\_{0,\text{lo}}$$
   - $p\_{0,\text{lo}}$ is the exact lower 64 bits of the final result (`lo`).
   - $p\_{0,\text{hi}}$ is a carry into the middle limb.

### 6.3 Final Assembly Formula
Combining the non-vanishing contributions (all six computed products: $c\_1 c\_2$, $c\_1 b\_2$, $b\_1 c\_2$, $c\_1 a\_2$, $b\_1 b\_2$, $a\_1 c\_2$):

$$\text{lo} = p\_{0,\text{lo}}$$

$$\text{mid}\_{\text{sum}} = p\_{0,\text{hi}} + p\_{1,\text{lo}} + p\_{2,\text{lo}}, \qquad \text{mid} = \text{mid}\_{\text{sum}} \bmod 2^{64}$$

$$\text{carry}\_{\text{mid}} = \lfloor \text{mid}\_{\text{sum}} / 2^{64} \rfloor + p\_{1,\text{hi}} + p\_{2,\text{hi}}$$

$$\text{hi} = \big(\text{carry}\_{\text{mid}} + p\_{3,\text{lo}} + p\_{4,\text{lo}} + p\_{5,\text{lo}}\big) \bmod 2^{64}$$

where $p\_1 = c\_1 \cdot b\_2$, $p\_2 = b\_1 \cdot c\_2$ (the two weight-$2^{64}$ products), and $p\_3 = c\_1 \cdot a\_2$, $p\_4 = b\_1 \cdot b\_2$, $p\_5 = a\_1 \cdot c\_2$ (the three weight-$2^{128}$ products, low halves only).

**No-overflow guarantee:** All intermediate sums (`mid_sum`, `carry_mid`, and the final `hi` accumulation) are carried out in `u128`. Each is a sum of at most four 64-bit values plus a small carry, so the maximum possible accumulator value is well under $2^{128}$ — no intermediate step can silently wrap, unlike the final `hi` truncation which is an intentional `as u64` cast dropping bits $\ge 2^{192}$.

---

## 7. Mathematical Proof: Signed vs Unsigned Multiplicative Congruence

> **Theorem:** For any two signed 192-bit integers $X, Y \in [-2^{191}, 2^{191}-1]$, performing unsigned modular multiplication on their 192-bit bit patterns produces the exact signed two's complement bit pattern for $(X \cdot Y) \bmod 2^{192}$.

### *Proof:*
Let $X, Y \in \mathbb{Z}$ be signed integers. In two's complement binary representation of width $N = 192$, the unsigned bit pattern $U(Z)$ corresponding to an integer $Z$ satisfies the congruence:

$$U(Z) \equiv Z \pmod{2^N}$$

Specifically:
- If $Z \ge 0$, then $U(Z) = Z$.
- If $Z \lt 0$, then $U(Z) = Z + 2^N$.

Now consider the unsigned multiplication of $U(X)$ and $U(Y)$:

$$U(X) \cdot U(Y) = (X + k\_1 \cdot 2^N)(Y + k\_2 \cdot 2^N) \quad \text{where } k\_1, k\_2 \in \lbrace 0, 1 \rbrace$$

Expanding the algebraic product:

$$U(X) \cdot U(Y) = X \cdot Y + k\_2 X \cdot 2^N + k\_1 Y \cdot 2^N + k\_1 k\_2 \cdot 2^{2N}$$

Factoring out $2^N$:

$$U(X) \cdot U(Y) = X \cdot Y + 2^N \cdot \underbrace{(k\_2 X + k\_1 Y + k\_1 k\_2 \cdot 2^N)}\_{\in \mathbb{Z}}$$

Taking the modulo $2^N$ of both sides:

$$U(X) \cdot U(Y) \equiv X \cdot Y \pmod{2^N}$$

Since the canonical ring representative in $[0, 2^N-1]$ is identical for both expressions, the bit-level representation produced by unsigned modular multiplication is **identical** to that of signed two's complement multiplication. $\blacksquare$

*Significance:* We do not need expensive sign-extension, conditional absolute-value conversions, or sign-restoration steps. We compute pure unsigned limb multiplications directly, exactly as §6 does.

---

## 8. Mathematical Verification of Invariant Edge Cases

### 8.1 Invariant: $(2^{64})^2 = 2^{128}$ Lands Exactly on the `hi` Limb
Let $X = Y = 2^{64}$, represented as `I192::new(0, 1, 0)` (i.e. $a=0, b=1, c=0$).
- $c\_1 c\_2 = 0 \implies \text{lo} = 0$.
- $c\_1 b\_2 = 0$, $b\_1 c\_2 = 0 \implies \text{mid} = 0$.
- $b\_1 b\_2 = 1 \cdot 1 = 1 \implies$ contributes $1$ to `hi`; $a\_1 c\_2 = c\_1 a\_2 = 0$.
- **Result:** `I192::new(1, 0, 0)`, i.e. $2^{128}$. Matches `test_mul_with_carry`.

### 8.2 Invariant: Modular Square $(2^{129}-1)^2 \equiv -2^{130} + 1 \pmod{2^{192}}$
Consider $X = 2^{129} - 1 = 1 \cdot 2^{128} + (2^{64}-1) \cdot 2^{64} + (2^{64}-1)$, i.e. `I192::new(1, -1, -1)`.
- Algebraic expansion:
  $$(2^{129}-1)^2 = (2^{129})^2 - 2 \cdot 2^{129} + 1 = 2^{258} - 2^{130} + 1$$
- Modulo $2^{192}$:
  $$2^{258} = 2^{66} \cdot 2^{192} \equiv 0 \pmod{2^{192}}$$
  $$(2^{129}-1)^2 \equiv -2^{130} + 1 \pmod{2^{192}}$$
- Decomposing $-2^{130} + 1$ into radix-$2^{64}$ limbs:
  $$-2^{130} + 1 = -4 \cdot 2^{128} + 0 \cdot 2^{64} + 1$$
  - High Limb: $-4$
  - Middle Limb: $0$
  - Low Limb: $+1$
- **Result:** `I192::new(-4, 0, 1)`. Matches `test_mul_large`.

### 8.3 Invariant: Negation Is a Two-Stage Carry Chain, Verified Against an Arbitrary-Precision Oracle
As derived in §3.5, `I192::MINUS_ONE.neg()` must equal `I192::ONE = new(0, 0, 1)`. This specific case — where the low limb produces *no* carry ($c\_1=0$) while the middle limb's inverted value is naturally already zero — is exactly the boundary condition that distinguishes a correct `overflowing_add`-based carry chain from the superficially similar but incorrect `(mid == 0)` heuristic. Beyond this single case, the full carry/borrow/negation/multiplication implementation was cross-checked against Python's arbitrary-precision integers over hundreds of randomized 192-bit operands plus boundary values ($0$, $\pm 1$, $\pm 2^{63}$, $\pm 2^{64}$, $\pm 2^{127}$, $\pm(2^{191}-1)$, $-2^{191}$), with no discrepancies after the fix in §3.5.

---

## 9. Summary of Architectural & Mathematical Theorems

| **Operation** | **Mathematical Formula** | **Hardware Translation** |
| :--- | :--- | :--- |
| **Negation** $(-X)$ | $-X = \sim X + 1 \pmod{2^{192}}$, carries via `overflowing_add` at every stage | `NOT, ADD, ADC, ADC / NEG` |
| **Addition** $(A + B)$ | $(A\_{\text{hi}}+B\_{\text{hi}}+c\_2)\cdot 2^{128} + (A\_{\text{mid}}+B\_{\text{mid}}+c\_1 \bmod 2^{64})\cdot 2^{64} + (A\_{\text{lo}}+B\_{\text{lo}} \bmod 2^{64})$ | `ADD, ADC, ADC (Carry Flag)` |
| **Subtraction** $(A - B)$ | $(A\_{\text{hi}}-B\_{\text{hi}}-b\_2)\cdot 2^{128} + (A\_{\text{mid}}-B\_{\text{mid}}-b\_1 \bmod 2^{64})\cdot 2^{64} + (A\_{\text{lo}}-B\_{\text{lo}} \bmod 2^{64})$ | `SUB, SBB, SBB (Borrow Flag)` |
| **Multiplication** $(A \cdot B)$ | $\text{lo} + \big(p\_{0,\text{hi}}+p\_{1,\text{lo}}+p\_{2,\text{lo}}\big)\cdot 2^{64} + \big(\text{carry}\_{\text{mid}}+p\_{3,\text{lo}}+p\_{4,\text{lo}}+p\_{5,\text{lo}}\big)\cdot 2^{128}$ | `6×MULX, ADD, ADC` |

1. **Ring Isomorphism:** Unsigned multiplication over modular integer rings $\mathbb{Z}/2^{192}\mathbb{Z}$ is homomorphic to signed two's complement multiplication.
2. **Carry Correctness Requires the Real Overflow Flag:** For any limb chain longer than two limbs, a "result-is-zero" carry heuristic is only sound at the *first* stage (where the addend is the fixed constant `1`); every subsequent stage has a variable carry-in and must derive its carry-out from `overflowing_add`/`overflowing_sub`, not from inspecting the result (§3.3–§3.5).
3. **Radix $2^{64}$ Reuse:** The three-limb base-$2^{64}$ layout lets every partial product be computed with a single native `u64 × u64 → u128` multiply (`mul_u64`), needing no manual 32-bit sub-decomposition the way I256's `mul_u128` helper needs a 64-bit one.
