# CS Tutorial
**Author**: flyyee

**Category**: Pwn

Flag: `SEE{Field_st4nd4rd_0perating_proc3dures_6867f14146419d08}`

## Description

Did you come to class prepared? Flag is at `/flag`.

## Difficulty

Medium

# Solution
- Request a large chunk such that mmap is use to allocate, leaking a libc address.
- Use the OOB array access to copy the stdout struct.
- Forge a file structure to give us a read into the actual stdin struct. We cannot directly get RCE because we only have 0x90 bytes, so we are unable to overwrite codecvt, wide_data, vtable etc.
- Use the buffer overflow in the second write to overwrite buffers[2] to our forged file structure.
- When fread is called for the final time, it uses our overwritten fp, which gives us an additional write into stdin as previously set up.
- Use our read into stdin to craft our RCE, e.g. we can use House of Apple.