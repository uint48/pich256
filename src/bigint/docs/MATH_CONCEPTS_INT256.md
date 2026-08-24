# Mathematical Foundations of 256-Bit Signed Integer Arithmetic (`I256`)

## 1. Radix-$2^{128}$ Multi-Precision Representation

### 1.1 Positional Numeral Systems in Base $B = 2^{128}$
A standard 64-bit or 128-bit CPU cannot natively represent a 256-bit scalar integer in a single register. We represent large numbers using a **positional base-$B$ numeral system** (also called *multi-limb representation*), where the radix is chosen to match the largest native word size:

$$B = 2^{128}$$

Any 256-bit integer $X$ is partitioned into two 128-bit "limbs":
- **Low Limb ($X_{\text{lo}}$):** The least significant 128 bits, having weight $B^0 = 2^0 = 1$.
- **High Limb ($X_{\text{hi}}$):** The most significant 128 bits, having weight $B^1 = 2^{128}$.

$$X = X_{\text{hi}} \cdot 2^{128} + X_{\text{lo}}$$

```
┌──────────────────────────────────────┬──────────────────────────────────────┐
│        High Limb (hi): 128 bits      │        Low Limb (lo): 128 bits       │
│           Bits [255 .. 128]          │           Bits [127 .. 0]            │
│            Weight: 2¹²⁸              │             Weight: 2⁰               │
│        Carries the Sign Bit          │       Pure Unsigned Magnitude        │
└──────────────────────────────────────┴──────────────────────────────────────┘
◄────────────────────────────── Total: 256 Bits ──────────────────────────────►
```

### 1.2 The Limb Role Asymmetry
Although in Rust both limbs are stored inside `i128` containers for struct symmetry, their mathematical roles are asymmetric:
1. **$X_{\text{lo}}$ is strictly an unsigned magnitude:**
   $$X_{\text{lo}} \in [0, 2^{128} - 1]$$
   During arithmetic (addition, subtraction, multiplication), $X_{\text{lo}}$ is cast to `u128`. It represents pure numerical value modulo $2^{128}$.
2. **$X_{\text{hi}}$ carries the sign bit:**
   $$X_{\text{hi}} \in [-2^{127}, 2^{127} - 1]$$
   Bit 127 of $X_{\text{hi}}$ is Bit 255 of the overall `I256` integer, dictating the sign in two's complement representation.

---

## 2. The Two's Complement Ring $\mathbb{Z} / 2^{256}\mathbb{Z}$

### 2.1 Formal Two's Complement Mapping
The type `I256` is an element of the quotient ring $\mathbb{Z} / 2^{256}\mathbb{Z}$. A 256-bit sequence $(b_{255}, b_{254}, \dots, b_1, b_0) \in \{0, 1\}^{256}$ maps to a signed integer via:

$$V(X) = -b_{255} \cdot 2^{255} + \sum_{i=0}^{254} b_i \cdot 2^i$$

The domain of representable values is:

$$X \in [-2^{255}, \; 2^{255} - 1]$$

- **Minimum value ($\text{MIN}$):** $-2^{255} = -57896044618658097711785492504343953926634992332820282019728792003956564819968$
- **Maximum value ($\text{MAX}$):** $+2^{255} - 1 = +57896044618658097711785492504343953926634992332820282019728792003956564819967$

### 2.2 Constant Identities and Limb Values

| Constant Identity | High Limb (`hi`) | Low Limb (`lo`) | 256-bit Hexadecimal | Mathematical Value |
| :--- | :--- | :--- | :--- | :--- |
| `I256::ZERO` | `0` | `0` | `0x0000000000000000...00000000` | $0$ (Additive Identity) |
| `I256::ONE` | `0` | `1` | `0x0000000000000000...00000001` | $+1$ (Multiplicative Identity) |
| `I256::MINUS_ONE` | `-1` | `-1` | `0xFFFFFFFFFFFFFFFF...FFFFFFFF` | $-1 \equiv 2^{256}-1 \pmod{2^{256}}$ |
| `I256::MAX` | `i128::MAX` (`0x7FFF...`) | `-1` (`0xFFFF...`) | `0x7FFFFFFFFFFFFFFF...FFFFFFFF` | $+2^{255}-1$ |
| `I256::MIN` | `i128::MIN` (`0x8000...`) | `0` (`0x0000...`) | `0x8000000000000000...00000000` | $-2^{255}$ |

#### Why `MINUS_ONE` is `new(-1, -1)`:
In two's complement, $-1 \pmod{2^{256}} = 2^{256} - 1 = \sum_{i=0}^{255} 2^i$, which consists of 256 ones (`0xFF...FF`).
- Lower 128 bits: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` = `u128::MAX` = `-1 as i128`.
- Upper 128 bits: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` = `u128::MAX` = `-1 as i128`.

---

## 3. Bitwise Negation (`std::ops::Neg`) & Carry Propagation

### 3.1 Mathematical Definition
Two's complement negation is algebraically defined as bitwise inversion plus 1:

$$-X = (\sim X) + 1 \pmod{2^{256}}$$

Where $\sim X$ is the bitwise NOT operation ($\sim X = (2^{256} - 1) - X$).

### 3.2 Two-Stage Limb Evaluation
When breaking $X = (X_{\text{hi}} \cdot 2^{128} + X_{\text{lo}})$ into limbs:

$$\sim X = (\sim X_{\text{hi}}) \cdot 2^{128} + (\sim X_{\text{lo}})$$

Adding 1 gives:

$$-X = (\sim X_{\text{hi}}) \cdot 2^{128} + (\sim X_{\text{lo}} + 1)$$

If $(\sim X_{\text{lo}} + 1)$ reaches $2^{128}$, it wraps around to $0$ and produces a carry $c_{\text{neg}} = 1$ to the high limb:

1. **Low Limb Calculation:**
   $$\text{lo} = (\sim X_{\text{lo}} + 1) \bmod 2^{128}$$

2. **Carry Condition:**
   $$c_{\text{neg}} = \begin{cases} 1 & \text{if } \sim X_{\text{lo}} + 1 = 2^{128} \iff X_{\text{lo}} = 0 \\ 0 & \text{otherwise} \end{cases}$$

3. **High Limb Calculation:**
   $$\text{hi} = \sim X_{\text{hi}} + c_{\text{neg}} \bmod 2^{128}$$

```
X:           [      X_hi      ]  [      X_lo      ]
                      │                     │
Bitwise NOT: [     ~X_hi      ]  [     ~X_lo      ]
                                            │ + 1
                                 [  lo = (~X_lo + 1) mod 2¹²⁸  ]
                      │                     │
Carry:                └──◄─── (lo == 0) ────┘
                      │
             [ hi = ~X_hi + carry ]
```

### 3.3 Theorem: The `lo == 0` Carry Invariant
> **Theorem:** For any unsigned 128-bit integer $X_{\text{lo}} \in [0, 2^{128}-1]$,
> $$(\sim X_{\text{lo}} + 1) \equiv 0 \pmod{2^{128}} \iff X_{\text{lo}} = 0$$

*Proof:*
- Bitwise inversion is $\sim X_{\text{lo}} = (2^{128} - 1) - X_{\text{lo}}$.
- Adding 1: $(\sim X_{\text{lo}}) + 1 = 2^{128} - X_{\text{lo}}$.
- For this quantity to equal $2^{128}$ (i.e. $0 \bmod 2^{128}$), we require $2^{128} - X_{\text{lo}} = 2^{128} \implies X_{\text{lo}} = 0$.
- For all other values $X_{\text{lo}} \in [1, 2^{128}-1]$, the result is strictly in $[1, 2^{128}-1]$, hence $\text{lo} \neq 0$ and carry is $0$. $\blacksquare$

### 3.4 Edge Case: $-(-2^{255}) = -2^{255}$
For $X = \text{MIN} = -2^{255}$ (`hi = i128::MIN`, `lo = 0`):
1. $\text{lo} = (!0 + 1) = 0$, producing carry $c_{\text{neg}} = 1$.
2. $\text{hi} = (!\text{i128::MIN}) + 1 = \text{0x7FFF...FFFF} + 1 = \text{0x8000...0000} = \text{i128::MIN}$.
3. Result is `I256::new(i128::MIN, 0) == I256::MIN`.
This correctly mirrors the two's complement asymmetric range where $-\text{MIN} = \text{MIN}$ due to modular wrap-around.

---

## 4. Multi-Limb Addition (`std::ops::Add`) with Carry

### 4.1 Algebraic Formulation
Let $A = A_{\text{hi}} \cdot 2^{128} + A_{\text{lo}}$ and $B = B_{\text{hi}} \cdot 2^{128} + B_{\text{lo}}$. The sum is:

$$A + B = (A_{\text{hi}} + B_{\text{hi}}) \cdot 2^{128} + (A_{\text{lo}} + B_{\text{lo}})$$

Because $A_{\text{lo}}, B_{\text{lo}} \in [0, 2^{128}-1]$, their sum satisfies:

$$0 \le A_{\text{lo}} + B_{\text{lo}} \le 2 \cdot (2^{128}-1) = 2^{129} - 2$$

We decompose the lower sum using the quotient and remainder with respect to $2^{128}$:

$$A_{\text{lo}} + B_{\text{lo}} = c \cdot 2^{128} + \text{lo}_{\text{sum}}$$

Where:
- $\text{lo}_{\text{sum}} = (A_{\text{lo}} + B_{\text{lo}}) \bmod 2^{128}$
- $c = \lfloor (A_{\text{lo}} + B_{\text{lo}}) / 2^{128} \rfloor \in \{0, 1\}$ (The Carry Flag)

Substituting back:

$$A + B = (A_{\text{hi}} + B_{\text{hi}} + c) \cdot 2^{128} + \text{lo}_{\text{sum}}$$

```
       A_hi                A_lo
+      B_hi                B_lo
────────────────────────────────────────────────
  (A_hi + B_hi + c)    (A_lo + B_lo) mod 2¹²⁸
          ▲                   │
          └───── Carry (c) ───┘
```

### 4.2 Step-by-Step Numerical Example
Consider adding $A = (10 \cdot 2^{128} + (2^{128}-1))$ and $B = (5 \cdot 2^{128} + 1)$:
- In code: `A = I256::new(10, -1)`, `B = I256::new(5, 1)`.
- $A_{\text{lo}} = 2^{128}-1 = \text{0xFFFF...FFFF}$, $B_{\text{lo}} = 1$.
- Low addition: $(2^{128}-1) + 1 = 2^{128} = 1 \cdot 2^{128} + 0$.
  - `lo = 0`
  - `carry = 1`
- High addition: $A_{\text{hi}} + B_{\text{hi}} + c = 10 + 5 + 1 = 16$.
- **Result:** $C = \text{I256::new}(16, 0) = 16 \cdot 2^{128} + 0$.

---

## 5. Multi-Limb Subtraction (`std::ops::Sub`) with Borrow

### 5.1 Algebraic Formulation
Let $A = A_{\text{hi}} \cdot 2^{128} + A_{\text{lo}}$ and $B = B_{\text{hi}} \cdot 2^{128} + B_{\text{lo}}$. The difference is:

$$A - B = (A_{\text{hi}} - B_{\text{hi}}) \cdot 2^{128} + (A_{\text{lo}} - B_{\text{lo}})$$

If $A_{\text{lo}} < B_{\text{lo}}$, the difference $(A_{\text{lo}} - B_{\text{lo}})$ is negative (in the range $[-(2^{128}-1), -1]$). In unsigned modular arithmetic, subtracting 1 from the next higher limb provides a "borrow" of $2^{128}$:

$$A_{\text{lo}} - B_{\text{lo}} = -b \cdot 2^{128} + \text{lo}_{\text{diff}}$$

Where:
- $b = \begin{cases} 1 & \text{if } A_{\text{lo}} < B_{\text{lo}} \\ 0 & \text{if } A_{\text{lo}} \ge B_{\text{lo}} \end{cases}$ (The Borrow Flag)
- $\text{lo}_{\text{diff}} = (A_{\text{lo}} - B_{\text{lo}} + b \cdot 2^{128}) \bmod 2^{128}$

Substituting back:

$$A - B = (A_{\text{hi}} - B_{\text{hi}} - b) \cdot 2^{128} + \text{lo}_{\text{diff}}$$

```
       A_hi                A_lo
-      B_hi                B_lo
────────────────────────────────────────────────
  (A_hi - B_hi - b)    (A_lo - B_lo) mod 2¹²⁸
          ▲                   │
          └──── Borrow (b) ───┘
```

### 5.2 Step-by-Step Numerical Example
Consider subtracting $B = (10 \cdot 2^{128} + 1)$ from $A = (20 \cdot 2^{128} + 0)$:
- In code: `A = I256::new(20, 0)`, `B = I256::new(10, 1)`.
- Low subtraction: $A_{\text{lo}} - B_{\text{lo}} = 0 - 1 = -1 \equiv 2^{128}-1 \pmod{2^{128}}$.
  - `lo = -1 as i128` (`0xFFFF...FFFF`)
  - `borrow = 1`
- High subtraction: $A_{\text{hi}} - B_{\text{hi}} - b = 20 - 10 - 1 = 9$.
- **Result:** $C = \text{I256::new}(9, -1) = 9 \cdot 2^{128} + (2^{128}-1) = 10 \cdot 2^{128} - 1$.

---

## 6. Full 256-Bit Multiplication (`std::ops::Mul`) Modulo $2^{256}$

### 6.1 The 512-Bit Product Expansion
Let two 256-bit integers be $X = a \cdot 2^{128} + b$ and $Y = c \cdot 2^{128} + d$, where:
- $a = X_{\text{hi}}, \quad b = X_{\text{lo}}$
- $c = Y_{\text{hi}}, \quad d = Y_{\text{lo}}$

Expanding their algebraic product yields 4 partial terms:

$$X \cdot Y = (a \cdot 2^{128} + b)(c \cdot 2^{128} + d) = \underbrace{a c \cdot 2^{256}}_{\text{Term 1: Weight } 2^{256}} + \underbrace{a d \cdot 2^{128}}_{\text{Term 2: Weight } 2^{128}} + \underbrace{b c \cdot 2^{128}}_{\text{Term 3: Weight } 2^{128}} + \underbrace{b d}_{\text{Term 4: Weight } 2^0}$$

```
                a (hi)           b (lo)
×               c (hi)           d (lo)
────────────────────────────────────────────────
                                 b · d        (Weight 2⁰   -> span [0 .. 255])
                a · d                         (Weight 2¹²⁸ -> span [128 .. 383])
                b · c                         (Weight 2¹²⁸ -> span [128 .. 383])
+ a · c                                       (Weight 2²⁵⁶ -> span [256 .. 511])
────────────────────────────────────────────────
  [ DISCARD >= 2²⁵⁶ ] │ [ UPPER 128 (hi) ] │ [ LOWER 128 (lo) ]
```

### 6.2 Modulo $2^{256}$ Truncation Strategy
Because the output ring is $\mathbb{Z} / 2^{256}\mathbb{Z}$, any term with weight $\ge 2^{256}$ vanishes identically ($\equiv 0 \pmod{2^{256}}$):

1. **Term $a \cdot c \cdot 2^{256}$:**
   $$a \cdot c \cdot 2^{256} \equiv 0 \pmod{2^{256}}$$
   *Optimization:* We do not compute $a \cdot c$ at all!

2. **Cross Terms $a \cdot d$ and $b \cdot c$ (Weight $2^{128}$):**
   $$a \cdot d \cdot 2^{128} = ( (ad)_{\text{hi}} \cdot 2^{128} + (ad)_{\text{lo}} ) \cdot 2^{128} = (ad)_{\text{hi}} \cdot 2^{256} + (ad)_{\text{lo}} \cdot 2^{128} \equiv (ad)_{\text{lo}} \cdot 2^{128} \pmod{2^{256}}$$
   *Optimization:* We only need the lower 128 bits of $a \cdot d$ and $b \cdot c$. The higher bits $(ad)_{\text{hi}}$ scale into $\ge 2^{256}$ and are discarded.

3. **Lowest Term $b \cdot d$ (Weight $2^0$):**
   $$b \cdot d = (bd)_{\text{hi}} \cdot 2^{128} + (bd)_{\text{lo}}$$
   - $(bd)_{\text{lo}}$ is the exact lower 128 bits of the final 256-bit result.
   - $(bd)_{\text{hi}}$ is the carry into the upper 128 bits.

### 6.3 Final Assembly Formula
Combining the non-zero contributions:

$$\text{lo}_{\text{result}} = (bd)_{\text{lo}}$$

$$\text{hi}_{\text{result}} = \Big( (bd)_{\text{hi}} + (ad)_{\text{lo}} + (bc)_{\text{lo}} \Big) \bmod 2^{128}$$

$$\text{Result} = \text{hi}_{\text{result}} \cdot 2^{128} + \text{lo}_{\text{result}}$$

---

## 7. Mathematical Proof: Signed vs Unsigned Multiplicative Congruence

> **Theorem:** For any two signed 256-bit integers $X, Y \in [-2^{255}, 2^{255}-1]$, performing unsigned modular multiplication on their 256-bit bit patterns produces the exact signed two's complement bit pattern for $(X \cdot Y) \bmod 2^{256}$.

### *Proof:*
Let $X, Y \in \mathbb{Z}$ be signed integers. In two's complement binary representation of width $N = 256$, the unsigned bit pattern $U(Z)$ corresponding to an integer $Z$ satisfies the congruence:

$$U(Z) \equiv Z \pmod{2^N}$$

Specifically:
- If $Z \ge 0$, then $U(Z) = Z$.
- If $Z < 0$, then $U(Z) = Z + 2^N$.

Now consider the unsigned multiplication of $U(X)$ and $U(Y)$:

$$U(X) \cdot U(Y) = (X + k_1 \cdot 2^N)(Y + k_2 \cdot 2^N) \quad \text{where } k_1, k_2 \in \{0, 1\}$$

Expanding the algebraic product:

$$U(X) \cdot U(Y) = X \cdot Y + k_2 X \cdot 2^N + k_1 Y \cdot 2^N + k_1 k_2 \cdot 2^{2N}$$

Factoring out $2^N$:

$$U(X) \cdot U(Y) = X \cdot Y + 2^N \cdot \underbrace{(k_2 X + k_1 Y + k_1 k_2 \cdot 2^N)}_{\in \mathbb{Z}}$$

Taking the modulo $2^N$ of both sides:

$$U(X) \cdot U(Y) \equiv X \cdot Y \pmod{2^N}$$

Since the canonical ring representative in $[0, 2^N-1]$ is identical for both expressions, the bit-level representation produced by unsigned modular multiplication is **identical** to that of signed two's complement multiplication. $\blacksquare$

*Significance:* We do not need expensive sign-extension, conditional absolute-value conversions, or sign-restoration steps. We compute pure unsigned limb multiplications directly!

---

## 8. The 128-Bit Multiplier Engine (`mul_u128`)

### 8.1 64-Bit Sub-Limb Decomposition
To compute the full 256-bit product of two 128-bit unsigned integers $a \times b$ using standard 64-bit hardware instructions, we decompose each 128-bit integer in base $2^{64}$:

$$a = a_1 \cdot 2^{64} + a_0, \qquad b = b_1 \cdot 2^{64} + b_0$$

Where $a_0, a_1, b_0, b_1 \in [0, 2^{64}-1]$.

### 8.2 The Four Partial Products
Each 64-bit $\times$ 64-bit multiplication fits within a native 128-bit integer:

$$\begin{aligned}
p_0 &= a_0 \cdot b_0 \quad (\text{Weight } 2^0) \\
p_1 &= a_0 \cdot b_1 \quad (\text{Weight } 2^{64}) \\
p_2 &= a_1 \cdot b_0 \quad (\text{Weight } 2^{64}) \\
p_3 &= a_1 \cdot b_1 \quad (\text{Weight } 2^{128})
\end{aligned}$$

The total product is:

$$a \cdot b = p_3 \cdot 2^{128} + (p_1 + p_2) \cdot 2^{64} + p_0$$

### 8.3 Weight Column Alignment Matrix

```
Column:       [ Bits 255 .. 192 ]  [ Bits 191 .. 128 ]  [ Bits 127 .. 64 ]  [ Bits 63 .. 0 ]
Weight:             2¹⁹²                 2¹²⁸                 2⁶⁴                 2⁰
────────────────────────────────────────────────────────────────────────────────────────
p0 (a0·b0):                                             [   p0 >> 64     ]  [ p0 & mask    ]
p1 (a0·b1):                        [   p1 >> 64      ]  [   p1 & mask    ]
p2 (a1·b0):                        [   p2 >> 64      ]  [   p2 & mask    ]
p3 (a1·b1):   [   p3 >> 64      ]  [   p3 & mask     ]
────────────────────────────────────────────────────────────────────────────────────────
Assembly:     └─────────────── HIGH 128 BITS ────────┘  └────────── LOW 128 BITS ───────┘
```

### 8.4 Accumulation and Carry Propagation
1. **Middle Weight-$2^{64}$ Column:**
   We sum the upper 64 bits of $p_0$ with the lower 64 bits of $p_1$ and $p_2$:
   $$\text{mid} = (p_0 \gg 64) + (p_1 \ \& \ \text{mask}_{64}) + (p_2 \ \& \ \text{mask}_{64})$$

   *Maximum Value Analysis:*
   $$\text{mid}_{\text{max}} \le (2^{64}-1) + (2^{64}-1) + (2^{64}-1) = 3 \cdot 2^{64} - 3 < 2^{66}$$
   Because $\text{mid}_{\text{max}} < 2^{128}$, $\text{mid}$ never overflows a `u128`.

2. **Low 128-Bit Assembly:**
   $$\text{lo} = (p_0 \ \& \ \text{mask}_{64}) \mid ((\text{mid} \ \& \ \text{mask}_{64}) \ll 64)$$

3. **High 128-Bit Assembly:**
   We collect the carry from $\text{mid}$ ($\text{mid} \gg 64 \le 2$), the upper 64 bits of $p_1$ and $p_2$, and $p_3$:
   $$\text{hi} = p_3 + (\text{mid} \gg 64) + (p_1 \gg 64) + (p_2 \gg 64)$$

   *Maximum Value Analysis:*
   $$\text{hi}_{\text{max}} \le (2^{128} - 2 \cdot 2^{64} + 1) + 2 + (2^{64}-1) + (2^{64}-1) = 2^{128} - 2^{64} + 3 < 2^{128}$$
   Thus $\text{hi}$ fits within a 128-bit unsigned integer without overflow!

---

## 9. Mathematical Verification of Invariant Edge Cases

### 9.1 Invariant: Square of `I256::MIN` is $0 \pmod{2^{256}}$
Let $X = \text{MIN} = -2^{255}$. Its square is:

$$X^2 = (-2^{255})^2 = 2^{510}$$

Reducing modulo $2^{256}$:

$$2^{510} = 2^{254} \cdot 2^{256} \equiv 0 \pmod{2^{256}}$$

- In code: `hi = i128::MIN` (`-2^127`), `lo = 0`.
- In multiplication: $a = 2^{127}, b = 0, c = 2^{127}, d = 0$.
  - $b \cdot d = 0 \implies \text{lo} = 0, \text{hi}_{bd} = 0$.
  - $a \cdot d = 0 \implies \text{lo}_{ad} = 0$.
  - $b \cdot c = 0 \implies \text{lo}_{bc} = 0$.
  - $\text{hi} = 0 + 0 + 0 = 0$.
- **Result:** `I256::ZERO`. Validates that all powers $2^k$ with $k \ge 256$ cleanly vanish.

### 9.2 Invariant: Modular Square $(2^{129}-1)^2 \equiv -2^{130} + 1 \pmod{2^{256}}$
Consider $X = 2^{129} - 1 = 2 \cdot 2^{128} + (2^{128}-1)$.
- In code: `hi = 1`, `lo = -1 as i128` ($2^{128}-1$).
- Algebraic expansion:
  $$(2^{129}-1)^2 = (2^{129})^2 - 2 \cdot 2^{129} + 1 = 2^{258} - 2^{130} + 1$$
- Modulo $2^{256}$:
  $$2^{258} = 4 \cdot 2^{256} \equiv 0 \pmod{2^{256}}$$
  $$(2^{129}-1)^2 \equiv -2^{130} + 1 \pmod{2^{256}}$$
- Decomposing $-2^{130} + 1$ into Radix-$2^{128}$ limbs:
  $$-2^{130} + 1 = -4 \cdot 2^{128} + 1$$
  - High Limb: $-4$ (which is `i128::new(-4)`)
  - Low Limb: $+1$ (which is `1`)
- **Result:** `I256::new(-4, 1)`. Matches test suite validation perfectly!

---

## 10. Summary of Architectural & Mathematical Theorems

| **Operation** | **Mathematical Formula** | **Hardware Translation** |
| :--- | :--- | :--- |
| **Negation** $(-X)$ | $-X = \sim X + 1 \pmod{2^{256}}$ | `NOT, ADD, ADC / NEG` |
| **Addition** $(A + B)$ | $(A_{\text{hi}} + B_{\text{hi}} + c)\cdot 2^{128} + (A_{\text{lo}} + B_{\text{lo}} \bmod 2^{128})$ | `ADD, ADC (Carry Flag)` |
| **Subtraction** $(A - B)$ | $(A_{\text{hi}} - B_{\text{hi}} - b)\cdot 2^{128} + (A_{\text{lo}} - B_{\text{lo}} \bmod 2^{128})$ | `SUB, SBB (Borrow Flag)` |
| **Multiplication** $(A \cdot B)$ | $(bd)_{\text{lo}} + \big( (bd)_{\text{hi}} + (ad)_{\text{lo}} + (bc)_{\text{lo}} \big)\cdot 2^{128}$ | `4×MULX, ADD, ADC` |

1. **Ring Isomorphism:** Unsigned multiplication over modular integer rings $\mathbb{Z}/2^{256}\mathbb{Z}$ is homomorphic to signed two's complement multiplication.
2. **Branchless Execution:** Carry and borrow propagations evaluate via bitwise arithmetic and condition predicates (`lo == 0`, `overflowing_add`, `overflowing_sub`), eliminating data-dependent branch hazards.
3. **Radix-$2^{128}$ Optimality:** Minimizes the number of partial limb multiplications from 16 (in 64-bit base) down to 3 necessary 128-bit products for truncated 256-bit output.