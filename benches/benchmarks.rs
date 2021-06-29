use criterion::{criterion_group, criterion_main, Criterion};
use tpke::{
    batch_share_combine, key_generation::generate_keys, share_combine, Ciphertext, DecryptionShare,
    ThresholdEncryptionParameters,
};

pub fn bench_decryption(c: &mut Criterion) {
    use rand::SeedableRng;
    use rand_core::RngCore;

    const NUM_OF_TX: usize = 1000;

    #[derive(Debug, Clone)]
    pub struct TestingParameters {}

    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    fn share_combine_bench(threshold: usize, num_of_msgs: usize) -> impl Fn() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (epk, _, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, threshold, &mut rng,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(epk.encrypt_msg(&messages[j], ad[j], &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(privkeys[i].create_share(&ciphertexts[j], ad[j]).unwrap());
            }
        }

        let share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let ad_local: Vec<&[u8]> = ad.clone();
            let shares: Vec<Vec<DecryptionShare<TestingParameters>>> = dec_shares.clone();

            for i in 0..ciphertexts.len() {
                share_combine(c[i].clone(), ad_local[i], shares[i].clone()).unwrap();
            }
        };

        share_combine_prepared
    }

    fn batch_share_combine_bench(threshold: usize, num_of_msgs: usize) -> impl Fn() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (epk, svp, privkeys) = generate_keys::<TestingParameters, ark_std::rand::rngs::StdRng>(
            threshold, threshold, &mut rng,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(epk.encrypt_msg(&messages[j], ad[j], &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(privkeys[i].create_share(&ciphertexts[j], ad[j]).unwrap());
            }
        }

        let batch_share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let ad_local: Vec<&[u8]> = ad.clone();
            let shares: Vec<Vec<DecryptionShare<TestingParameters>>> = dec_shares.clone();

            batch_share_combine(c, ad_local, shares).unwrap();
        };

        batch_share_combine_prepared
    }

    let mut group = c.benchmark_group("TPKE");
    group.sample_size(10);

    // Benchmark `share_combine` across thresholds
    let a = share_combine_bench(08, 1);
    group.bench_function("share_combine: threshold 08", |b| b.iter(|| a()));
    group.measurement_time(core::time::Duration::new(30, 0));
    let a = share_combine_bench(32, 1);
    group.bench_function("share_combine: threshold 32", |b| b.iter(|| a()));
    group.measurement_time(core::time::Duration::new(60, 0));
    let a = share_combine_bench(64, 1);
    group.bench_function("share_combine: threshold 64", |b| b.iter(|| a()));

    // Benchmark `share_combine` and `batch_share_combine` across number of messages
    let a = share_combine_bench(08, 1);
    group.bench_function("share_combine_bench: threshold 08 - #msg 001", |b| {
        b.iter(|| a())
    });
    group.measurement_time(core::time::Duration::new(30, 0));
    let a = share_combine_bench(08, 10);
    group.bench_function("share_combine_bench: threshold 08 - #msg 010", |b| {
        b.iter(|| a())
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    let a = share_combine_bench(08, 100);
    group.bench_function("share_combine_bench: threshold 08 - #msg 100", |b| {
        b.iter(|| a())
    });

    let a = batch_share_combine_bench(08, 01);
    group.bench_function("batch_share_combine: threshold 08 - #msg 001", |b| {
        b.iter(|| a())
    });
    group.measurement_time(core::time::Duration::new(60, 0));
    let a = batch_share_combine_bench(08, 10);
    group.bench_function("batch_share_combine: threshold 08 - #msg 010", |b| {
        b.iter(|| a())
    });
    group.measurement_time(core::time::Duration::new(500, 0));
    let a = batch_share_combine_bench(08, 100);
    group.bench_function("batch_share_combine: threshold 08 - #msg 100", |b| {
        b.iter(|| a())
    });

    // Benchmarking for larger number of messages
    let a = share_combine_bench(08, 1000);
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("share_combine_bench: threshold 08 - #msg 1000", |b| {
        b.iter(|| a())
    });
    let a = batch_share_combine_bench(08, 1000);
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("batch_share_combine: threshold 08 - #msg 1000", |b| {
        b.iter(|| a())
    });
}

criterion_group!(benches, bench_decryption);
criterion_main!(benches);
