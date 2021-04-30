use criterion::{criterion_group, criterion_main, Criterion};
use tpke::{
    key_generation::generate_keys, share_combine, batch_share_combine, DecryptionShare, ThresholdEncryptionParameters, Ciphertext
};

pub fn bench_decryption(c: &mut Criterion) {
    // use a fixed seed for reproducability
    use rand::SeedableRng;
    use rand_core::RngCore;

    #[derive(Debug)]
    pub struct TestingParameters {}

    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut share_combine_bench = |threshold: usize, num_of_msgs: usize| {
        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, threshold, &mut rng,
        );

        let mut messages: Vec<[u8; 8]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; 8] = [0u8; 8];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(epk.encrypt_msg(&messages[j], ad[j], &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[0].push(privkeys[i].create_share(&ciphertexts[0], ad[j]).unwrap());
            }
            share_combine(ciphertexts.pop().unwrap(), ad[j], dec_shares.pop().unwrap()).unwrap();
        }
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut batch_share_combine_bench = |threshold: usize, num_of_msgs: usize| {
        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, threshold, &mut rng,
        );

        let msg: &[u8] = "abc".as_bytes();
        let ad: &[u8] = "".as_bytes();
        let ciphertext = epk.encrypt_msg(msg, ad, &mut rng);

        let mut dec_shares: Vec<DecryptionShare<TestingParameters>> = Vec::new();
        for i in 0..threshold {
            dec_shares.push(privkeys[i].create_share(&ciphertext, ad).unwrap());
            dec_shares[i].verify_share(&ciphertext, ad, &svp);
        }

        let mut messages: Vec<[u8; 8]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; 8] = [0u8; 8];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(epk.encrypt_msg(&messages[j], ad[j], &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(privkeys[i].create_share(&ciphertexts[j], ad[j]).unwrap());
            }
        }

        batch_share_combine(ciphertexts, ad, dec_shares).unwrap();
    };

    let mut group = c.benchmark_group("TPKE");
    group.sample_size(10);

    // Benchmark `share_combine` across thresholds
    group.bench_function("share_combine: threshold 08", |b| b.iter(|| share_combine_bench(08, 1)));
    group.measurement_time(core::time::Duration::new(30, 0));
    group.bench_function("share_combine: threshold 32", |b| b.iter(|| share_combine_bench(32, 1)));
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("share_combine: threshold 64", |b| b.iter(|| share_combine_bench(64, 1)));

    // Benchmark `share_combine` and `batch_share_combine` across number of messages
    group.bench_function("share_combine_bench: threshold 08 - #msg 001", |b| b.iter(|| share_combine_bench(08, 1)));
    group.measurement_time(core::time::Duration::new(30, 0));
    group.bench_function("share_combine_bench: threshold 08 - #msg 010", |b| b.iter(|| share_combine_bench(08, 10)));
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("share_combine_bench: threshold 08 - #msg 100", |b| b.iter(|| share_combine_bench(08, 100)));

    group.bench_function("batch_share_combine: threshold 08 - #msg 001", |b| b.iter(|| batch_share_combine_bench(08, 1)));
    group.measurement_time(core::time::Duration::new(60, 0));
    group.bench_function("batch_share_combine: threshold 08 - #msg 010", |b| b.iter(|| batch_share_combine_bench(08, 10)));
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("batch_share_combine: threshold 08 - #msg 100", |b| b.iter(|| batch_share_combine_bench(08, 100)));

    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("share_combine_bench: threshold 08 - #msg 1000", |b| b.iter(|| share_combine_bench(08, 1000)));
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("batch_share_combine: threshold 08 - #msg 1000", |b| b.iter(|| batch_share_combine_bench(08, 1000)));
}

criterion_group!(benches, bench_decryption);
criterion_main!(benches);
