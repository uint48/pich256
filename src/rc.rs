// Round Constants (RC)
pub const RCS: [i16; 16] = [
    1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987,
];

// Expanded to 64 bits via 4-fold replication (p)
pub fn p(input: i16) -> i64 {
    let x = input;
    let mut y: i64 = 0;

    y = (x as i64) << 48;
    y |= (x as i64) << 32;
    y |= (x as i64) << 16;
    y |= x as i64;

    y
}