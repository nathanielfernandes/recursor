pub struct PacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl PacketBuffer {
    const LEN: usize = 512;

    // fresh packet buffer
    pub fn new() -> PacketBuffer {
        PacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[0..self.pos]
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    // step forward in the buffer by n steps
    // bounds checking is done during read
    #[inline]
    pub fn step(&mut self, n: usize) {
        self.pos += n;
    }

    // set the buffer position
    #[inline]
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline]
    pub fn get(&self, pos: usize) -> Result<u8, &'static str> {
        if pos >= Self::LEN {
            return Err("out of bounds");
        }

        Ok(self.buf[pos])
    }

    #[inline]
    pub fn get_range(&self, start: usize, end: usize) -> Result<&[u8], &'static str> {
        if start + end >= Self::LEN {
            return Err("out of bounds");
        }

        Ok(&self.buf[start..end])
    }

    #[inline]
    pub fn read_slice<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        if self.pos + N >= Self::LEN {
            return Err("end of buffer");
        }

        let mut arr = [0; N];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.step(N);

        Ok(arr)
    }

    // read a byte from the buffer, and step forward
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, &'static str> {
        if self.pos >= Self::LEN {
            return Err("end of buffer");
        }

        let byte = self.buf[self.pos];
        self.step(1);
        Ok(byte)
    }

    // read 2 bytes from the buffer, and step forward
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16, &'static str> {
        if self.pos + 2 >= Self::LEN {
            return Err("end of buffer");
        }

        let val = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);

        self.step(2);

        Ok(val)
    }

    // read 4 bytes from the buffer, and step forward
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32, &'static str> {
        if self.pos + 4 >= Self::LEN {
            return Err("end of buffer");
        }

        let val = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);

        self.step(4);

        Ok(val)
    }

    // read a qname from the buffer
    // qname is a series of labels, each prefixed with a length byte
    // the qname is terminated with a zero length byte
    // the qname is read from the current position, and the position is updated
    // to the end of the qname
    pub fn read_qname(&mut self, out: &mut String) -> Result<(), &'static str> {
        let mut pos = self.pos;

        // keep track of how many jumps we've done
        const MAX_JUMPS: usize = 5;
        let mut jumped = false;
        let mut jumps = 0;

        // delimeter which is appended to each label
        let mut delimeter = '\0';
        loop {
            // protect against jumping forever
            if jumps > MAX_JUMPS {
                return Err("too many jumps (5)");
            }

            // read the length byte
            let len = self.get(pos)?;

            // check if this is a jump
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2);
                }

                // calculate the offset
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // update the number of jumps
                jumps += 1;
                jumped = true;

                continue;
            } else {
                // move past the length byte
                pos += 1;

                // check for zero length
                if len == 0 {
                    break;
                }

                // write the delimeter
                if delimeter != '\0' {
                    out.push(delimeter);
                }

                let label = self.get_range(pos, pos + len as usize)?;
                out.push_str(&String::from_utf8_lossy(label).to_lowercase());

                // update the delimeter
                delimeter = '.';

                // move forward
                pos += len as usize;
            }
        }

        // step forward to the end of the qname
        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    #[inline]
    pub fn write_u8(&mut self, val: u8) -> Result<(), &'static str> {
        if self.pos >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[self.pos] = val;
        self.step(1);

        Ok(())
    }

    #[inline]
    pub fn write_u16(&mut self, val: u16) -> Result<(), &'static str> {
        if self.pos + 2 >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[self.pos..self.pos + 2].copy_from_slice(&val.to_be_bytes());
        self.step(2);

        Ok(())
    }

    #[inline]
    pub fn write_u32(&mut self, val: u32) -> Result<(), &'static str> {
        if self.pos + 4 >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[self.pos..self.pos + 4].copy_from_slice(&val.to_be_bytes());
        self.step(4);

        Ok(())
    }

    #[inline]
    pub fn write_slice<const N: usize>(&mut self, slice: &[u8; N]) -> Result<(), &'static str> {
        if self.pos + N >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[self.pos..self.pos + N].copy_from_slice(slice);
        self.step(N);
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<(), &'static str> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                return Err("label too long (max 63 bytes)");
            }

            // write the length byte
            self.write_u8(len as u8)?;

            // write the label
            for byte in label.as_bytes() {
                self.write_u8(*byte)?;
            }
        }

        // write the zero length byte
        self.write_u8(0)?;

        Ok(())
    }

    #[inline]
    pub fn set_u8(&mut self, pos: usize, val: u8) -> Result<(), &'static str> {
        if pos >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[pos] = val;
        Ok(())
    }

    #[inline]
    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), &'static str> {
        if pos + 2 >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[pos..pos + 2].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }

    #[inline]
    pub fn set_u32(&mut self, pos: usize, val: u32) -> Result<(), &'static str> {
        if pos + 4 >= Self::LEN {
            return Err("end of buffer");
        }

        self.buf[pos..pos + 4].copy_from_slice(&val.to_be_bytes());
        Ok(())
    }
}
