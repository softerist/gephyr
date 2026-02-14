pub fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            return Err("incomplete_data".to_string());
        }
        let byte = data[pos];
        result |= ((byte & 0x7F) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    Ok((result, pos))
}

pub fn skip_field(data: &[u8], offset: usize, wire_type: u8) -> Result<usize, String> {
    match wire_type {
        0 => {
            let (_, new_offset) = read_varint(data, offset)?;
            Ok(new_offset)
        }
        1 => Ok(offset + 8),
        2 => {
            let (length, content_offset) = read_varint(data, offset)?;
            Ok(content_offset + length as usize)
        }
        5 => Ok(offset + 4),
        _ => Err(format!("unknown_wire_type: {}", wire_type)),
    }
}

pub fn find_field(data: &[u8], target_field: u32) -> Result<Option<Vec<u8>>, String> {
    let mut offset = 0;

    while offset < data.len() {
        let (tag, new_offset) = match read_varint(data, offset) {
            Ok(v) => v,
            Err(_) => break,
        };

        let wire_type = (tag & 7) as u8;
        let field_num = (tag >> 3) as u32;

        if field_num == target_field && wire_type == 2 {
            let (length, content_offset) = read_varint(data, new_offset)?;
            return Ok(Some(
                data[content_offset..content_offset + length as usize].to_vec(),
            ));
        }

        offset = skip_field(data, new_offset, wire_type)?;
    }

    Ok(None)
}