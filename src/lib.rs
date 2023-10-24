use helpers::copy;

mod block;
mod helpers;

// The block size of the hash algorithm in bytes.
const BLOCK_SIZE: usize = 128;

#[derive(Clone)]
pub struct Blake512 {
    hash_size: usize,    // hash output size in bits (384 or 512)
    h: [u64; 8],         // current chain value
    s: [u64; 4],         // salt (zero by default)
    t: u64,              // message bits counter
    nullt: bool,         // special case for finalization: skip counter
    x: [u8; BLOCK_SIZE], // buffer for data not yet compressed
    nx: usize,           // number of bytes in buffer
}

static IV512: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

static IV384: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

impl Default for Blake512 {
    fn default() -> Self {
        Self {
            hash_size: 512,
            h: IV512,
            s: [0; 4],
            t: 0,
            nullt: false,
            x: [0; BLOCK_SIZE],
            nx: 0,
        }
    }
}

impl Blake512 {
    pub fn reset(&mut self) {
        if self.hash_size == 384 {
            self.h = IV384;
        } else {
            self.h = IV512;
        }
        self.t = 0;
        self.nx = 0;
        self.nullt = false;
    }

    fn size(&self) -> usize {
        self.hash_size >> 3
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn write(&mut self, p: &[u8]) -> u8 {
        let nn = p.len();
        let mut p = p;

        if self.nx > 0 {
            let n = std::cmp::min(p.len(), BLOCK_SIZE - self.nx);
            self.nx += copy(&mut self.x[self.nx..], p);

            if self.nx == BLOCK_SIZE {
                self.block(&self.x.clone());
                self.nx = 0;
            }

            p = &p[n..];
        }

        if p.len() >= BLOCK_SIZE {
            let n = p.len() & !(BLOCK_SIZE - 1);
            self.block(&p[..n]);
            p = &p[n..];
        }

        if !p.is_empty() {
            self.nx = copy(&mut self.x, p);
        }

        nn as u8
    }

    pub fn sum(&mut self, in_: &[u8]) -> Vec<u8> {
        let mut d = self.clone();
        // Make a copy of self so that caller can keep writing and summing.
        let nx = d.nx as u64;
        let l = d.t + (nx << 3);
        let mut len = [0u8; 16];

        // len[0 .. 7] = 0, because our counter has only 64 bits.
        len[8] = (l >> 56) as u8;
        len[9] = (l >> 48) as u8;
        len[10] = (l >> 40) as u8;
        len[11] = (l >> 32) as u8;
        len[12] = (l >> 24) as u8;
        len[13] = (l >> 16) as u8;
        len[14] = (l >> 8) as u8;
        len[15] = l as u8;

        if nx == 111 {
            // One padding byte.
            d.t -= 8;
            d.write(&[0x81]);
        } else {
            let mut pad = [0u8; 129];
            pad[0] = 0x80;
            if nx < 111 {
                // Enough space to fill the block.
                if nx == 0 {
                    d.nullt = true;
                }

                d.t = d.t.wrapping_sub(888 - (nx << 3));
                d.write(&pad[0..111 - nx as usize]);
            } else {
                // Need 2 compressions.
                d.t -= 1024 - (nx << 3);
                d.write(&pad[0..128 - nx as usize]);
                d.t -= 888;
                d.write(&pad[1..112]);
                d.nullt = true;
            }

            d.write(&[0x01]);

            d.t -= 8;
        }

        d.t -= 128;
        d.write(&len);

        let mut tmp: Vec<u8> = vec![0; d.size()];
        let mut j = 0;

        for s in d.h[..(d.hash_size >> 6)].iter() {
            tmp[j] = (s >> 56) as u8;
            tmp[j + 1] = (s >> 48) as u8;
            tmp[j + 2] = (s >> 40) as u8;
            tmp[j + 3] = (s >> 32) as u8;
            tmp[j + 4] = (s >> 24) as u8;
            tmp[j + 5] = (s >> 16) as u8;
            tmp[j + 6] = (s >> 8) as u8;
            tmp[j + 7] = *s as u8;
            j += 8;
        }

        let mut out: Vec<u8> = in_.to_vec();
        out.extend_from_slice(&tmp);
        out
    }

    pub fn set_salt(&mut self, s: &[u8]) {
        if s.len() != 32 {
            panic!("salt length must be 32 bytes");
        }

        let mut j = 0;
        for i in 0..4 {
            self.s[i] = (u64::from(s[j]) << 56)
                | (u64::from(s[j + 1]) << 48)
                | (u64::from(s[j + 2]) << 40)
                | (u64::from(s[j + 3]) << 32)
                | (u64::from(s[j + 4]) << 24)
                | (u64::from(s[j + 5]) << 16)
                | (u64::from(s[j + 6]) << 8)
                | u64::from(s[j + 7]);
            j += 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Blake512;

    const VECTORS_512: [(&str, &str); 7] = [
        (
            "1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451",
            "The quick brown fox jumps over the lazy dog",
        ),
        (
            "7bf805d0d8de36802b882e65d0515aa7682a2be97a9d9ec1399f4be2eff7de07684d7099124c8ac81c1c7c200d24ba68c6222e75062e04feb0e9dd589aa6e3b7",
            "BLAKE",
        ),
        (
            "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
            "",
        ),
        (
            "19bb3a448f4eef6f0b9374817e96c7c848d96f20c5a3e4b808173d97aede52cb396506ac20e174a1d53d9e51e443e7447855f2c9e8c6e4247fa8e4f54cda5897",
            "'BLAKE wins SHA-3! Hooray!!!' (I have time machine)",
        ),
        (
            "8cd8a7bf2953dd236371a07a3c9e70325abd76922dcb434c68532760e536cf2a955fe8c40d90cb38506fcde30b47da8ee8835064e091427d854ce1dfad972634",
            "Go",
        ),
        (
            "465d047d9695f258a47af7b94a03d903cb60ae1286f263aac8628774ee90828bea31fb7fe1d3385af364080a317115c8df8596c3c608d8de77b95bff702a3984",
            "HELP! I'm trapped in hash!",
        ),
        (
            "68376fe303ee09c3a220ee330bccc9fa9fba6dc41741507f195f5457ffa75864076f71bc07e94620123ec24f70458c2ba3dd1fa31a7fefc036d430c962c0969b",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est.",
        ),
    ];

    #[test]
    fn test_512_c() {
        // Test as in C program.
        let hashes = vec![
            vec![
                0x97, 0x96, 0x15, 0x87, 0xf6, 0xd9, 0x70, 0xfa, 0xba, 0x6d, 0x24, 0x78, 0x04, 0x5d,
                0xe6, 0xd1, 0xfa, 0xbd, 0x09, 0xb6, 0x1a, 0xe5, 0x09, 0x32, 0x05, 0x4d, 0x52, 0xbc,
                0x29, 0xd3, 0x1b, 0xe4, 0xff, 0x91, 0x02, 0xb9, 0xf6, 0x9e, 0x2b, 0xbd, 0xb8, 0x3b,
                0xe1, 0x3d, 0x4b, 0x9c, 0x06, 0x09, 0x1e, 0x5f, 0xa0, 0xb4, 0x8b, 0xd0, 0x81, 0xb6,
                0x34, 0x05, 0x8b, 0xe0, 0xec, 0x49, 0xbe, 0xb3,
            ],
            vec![
                0x31, 0x37, 0x17, 0xd6, 0x08, 0xe9, 0xcf, 0x75, 0x8d, 0xcb, 0x1e, 0xb0, 0xf0, 0xc3,
                0xcf, 0x9f, 0xC1, 0x50, 0xb2, 0xd5, 0x00, 0xfb, 0x33, 0xf5, 0x1c, 0x52, 0xaf, 0xc9,
                0x9d, 0x35, 0x8a, 0x2f, 0x13, 0x74, 0xb8, 0xa3, 0x8b, 0xba, 0x79, 0x74, 0xe7, 0xf6,
                0xef, 0x79, 0xca, 0xb1, 0x6f, 0x22, 0xCE, 0x1e, 0x64, 0x9d, 0x6e, 0x01, 0xad, 0x95,
                0x89, 0xc2, 0x13, 0x04, 0x5d, 0x54, 0x5d, 0xde,
            ],
        ];

        let data = vec![0u8; 144];

        let mut h = Blake512::default();
        h.write(&data[..1]);
        let sum = h.sum(&vec![]);
        if !sum.eq(&hashes[0]) {
            panic!("0: expected {:?}, got {:?}", hashes[0], sum);
        }

        // Try to continue hashing.
        h.write(&data[1..]);
        let sum = h.sum(&vec![]);
        if !sum.eq(&hashes[1]) {
            panic!("1(1): expected {:?}, got {:?}", hashes[1], sum);
        }

        // Try with reset.
        h.reset();
        h.write(&data);
        let sum = h.sum(&vec![]);
        if !sum.eq(&hashes[1]) {
            panic!("1(2): expected {:?}, got {:?}", hashes[1], sum);
        }
    }

    #[test]
    fn test_vectors_512() {
        test_vectors(&VECTORS_512);
    }

    fn test_vectors(vectors: &[(&str, &str)]) {
        for (i, v) in vectors.iter().enumerate() {
            let mut h = Blake512::default();
            h.write(v.1.as_bytes());
            let res = format!("{}", hex::encode(h.sum(&vec![])));
            if res != v.0 {
                panic!("{:?}: expected {:?}, got {:?}", i, v.0, res);
            }
        }
    }

    #[test]
    fn test_two_writes() {
        let mut b = vec![0u8; 65];
        for i in 0..65 {
            b[i] = i as u8;
        }

        let mut h1 = Blake512::default();
        h1.write(&b[0..1]);
        h1.write(&b[1..]);
        let sum1 = h1.sum(&vec![]);

        let mut h2 = Blake512::default();
        h2.write(&b);
        let sum2 = h2.sum(&vec![]);

        if sum1 != sum2 {
            panic!("Result of two writes differs from a single write with the same bytes");
        }
    }
}
