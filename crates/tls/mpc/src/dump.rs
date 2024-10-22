fn prepare_mac<Vm>(&mut self, vm: &mut Vm, record_count: usize) -> Result<GhashPrep, AesError>
where
    Vm: VmExt<Binary> + ViewExt<Binary>,
{
    let j0_blocks = self.compute_keystream(vm, record_count)?;

    let (mac_key, otp) = self.prepare_mac_key(vm)?;
    let role = self.config.role();

    let ghash = GhashPrep {
        role,
        otp,
        mac_key,
        j0_blocks,
    };

    Ok(ghash)
}

fn prepare_mac_key<Vm>(&self, vm: &mut Vm) -> Result<(Array<U8, 16>, [u8; 16]), AesError>
where
    Vm: VmExt<Binary> + ViewExt<Binary>,
{
    let zero: Array<U8, 16> = Self::alloc(vm, Visibility::Public)?;
    Self::asssign(vm, zero, [0_u8; 16])?;
    Self::commit(vm, zero)?;

    let mut rng = thread_rng();
    let mut otp_0: Array<U8, 16> = Self::alloc(vm, Visibility::Private)?;
    let otp_value: [u8; 16] = rng.gen();
    Self::asssign(vm, otp_0, otp_value)?;
    Self::commit(vm, otp_0)?;

    let mut otp_1: Array<U8, 16> = Self::alloc(vm, Visibility::Blind)?;
    Self::commit(vm, otp_1)?;

    if let Role::Follower = self.config.role() {
        std::mem::swap(&mut otp_0, &mut otp_1);
    }

    let aes_shared = CallBuilder::new(<Aes128 as CipherCircuit>::ecb_shared())
        .arg(self.key)
        .arg(zero)
        .arg(otp_0)
        .arg(otp_1)
        .build()
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    let mac_key: Array<U8, 16> = vm
        .call(aes_shared)
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    Ok((mac_key, otp_value))
}

fn decode_for_leader<R, Vm>(
    role: Role,
    vm: &mut Vm,
    value: R,
) -> Result<(R, Option<R::Clear>), AesError>
where
    R: Repr<Binary> + StaticSize<Binary> + Copy,
    R::Clear: Copy,
    Vm: VmExt<Binary> + ViewExt<Binary>,
    Standard: Distribution<R::Clear>,
{
    let (otp, otp_value): (R, Option<R::Clear>) = match role {
        Role::Leader => {
            let mut rng = thread_rng();
            let otp = Self::alloc(vm, Visibility::Private)?;
            let otp_value: R::Clear = rng.gen();

            Self::asssign(vm, otp, otp_value)?;
            Self::commit(vm, otp)?;

            (otp, Some(otp_value))
        }
        Role::Follower => {
            let otp = Self::alloc(vm, Visibility::Blind)?;
            Self::commit(vm, otp)?;

            (otp, None)
        }
    };

    let otp_circuit = CallBuilder::new(<Aes128 as CipherCircuit>::otp())
        .arg(value)
        .arg(otp)
        .build()
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    let value = vm
        .call(otp_circuit)
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    Ok((value, otp_value))
}

async fn decode_key_and_iv(
    &mut self,
    vm: &mut Vm,
    ctx: &mut Ctx,
) -> Result<
    Option<(
        <<Aes128 as CipherCircuit>::Key as Repr<Binary>>::Clear,
        <<Aes128 as CipherCircuit>::Iv as Repr<Binary>>::Clear,
    )>,
    Self::Error,
> {
    let (key, otp_key) = Self::decode_for_leader(self.config.role(), vm, self.key)?;
    let (iv, otp_iv) = Self::decode_for_leader(self.config.role(), vm, self.iv)?;

    let key = vm
        .decode(key)
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    let iv = vm
        .decode(iv)
        .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    vm.execute(ctx)
        .await
        .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;
    vm.flush(ctx)
        .await
        .map_err(|err| Self::Error::new(ErrorKind::Vm, err))?;

    let (mut key, mut iv) =
        futures::try_join!(key, iv).map_err(|err| AesError::new(ErrorKind::Vm, err))?;

    if let Role::Leader = self.config.role() {
        key.iter_mut()
            .zip(otp_key.expect("otp should be set for leader"))
            .for_each(|(value, otp)| *value ^= otp);
        iv.iter_mut()
            .zip(otp_iv.expect("otp should be set for leader"))
            .for_each(|(value, otp)| *value ^= otp);

        return Ok(Some((key, iv)));
    }

    Ok(None)
}

fn decrypt_private(&mut self, vm: &mut Vm, len: usize) -> Result<DecryptPrivate<Aes128>, AesError> {
    let block_count = (len / 16) + (len % 16 != 0) as usize;

    let mut keystream: Keystream<Aes128> = self.compute_keystream(vm, block_count)?;

    let otps: Option<Vec<[u8; 16]>> = match self.config.role() {
        Role::Leader => {
            let mut otps = Vec::with_capacity(keystream.len());
            for old_output in keystream.outputs.iter_mut() {
                let (new_output, otp) = Self::decode_for_leader(Role::Leader, vm, *old_output)?;
                *old_output = new_output;
                otps.push(otp.expect("Leader should get one-time pad"));
            }
            Some(otps)
        }
        Role::Follower => {
            for old_output in keystream.outputs.iter_mut() {
                let (new_output, _) = Self::decode_for_leader(Role::Follower, vm, *old_output)?;
                *old_output = new_output;
            }
            None
        }
    };

    let decrypt = DecryptPrivate { keystream, otps };

    Ok(decrypt)
}

// One TLS record fits 2^17 bits, and one AES block fits 2^7 bits.
// So we need one j0 block per 2^10 AES blocks.
// let record_count = (block_count >> 11) + (block_count % 1024);
