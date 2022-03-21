use std::{io, vec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{super::new_error, frame};

// fn get_next_frame_meta(&mut self) -> frame::FrameMetadata {
//     frame::FrameMetadata {
//         session_id: self.id,
//         option: 0,
//         target: match self.dest.as_ref() {
//             None => None,
//             Some(addr) => Some(frame::Destination {
//                 network: self.transfer_type,
//                 address: addr.clone(),
//             }),
//         },
//         session_status: if self.followup {
//             frame::SessionStatus::Keep
//         } else {
//             self.followup = true;
//             frame::SessionStatus::New
//         },
//     }
// }

#[inline]
pub async fn write_frame<S>(writer: &mut S, mut meta: frame::FrameMetadata, data: Option<&[u8]>) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if let Some(data) = data {
        if data.len() + 1 > 64 * 1024 * 1024 {
            return Err(new_error("value too large"));
        }

        frame::FrameOption::Data.set_to(&mut meta.option);

        let mut header = Vec::new();
        frame::encode_frame(&mut header, &meta)?;
        header.write_u16(data.len() as u16).await?;

        tokio::pin!(writer);
        writer.write_all(&header[..]).await?;
        writer.write_all(data).await?;
    } else {
        let mut header = Vec::new();
        frame::encode_frame(&mut header, &meta)?;
        tokio::pin!(writer);
        writer.write_all(&header[..]).await?;
    }

    Ok(())
}

pub async fn write_close_frame<S>(writer: &mut S, session_id: u16, has_error: bool) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut meta = frame::FrameMetadata {
        session_id,
        option: 0,
        target: None,
        session_status: frame::SessionStatus::End,
    };

    if has_error {
        frame::FrameOption::Error.set_to(&mut meta.option);
    }

    write_frame(writer, meta, None).await
}

pub async fn ignore_data<R>(reader: &mut R, meta: &frame::FrameMetadata) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    if !meta.has_data() {
        return Ok(());
    }

    let mut len = reader.read_u16().await? as usize;
    while len > 0 {
        let read_len = std::cmp::max(len, 4096);
        let mut buf = vec![0u8; read_len];
        reader.read_exact(&mut buf).await?;
        len -= read_len;
    }

    Ok(())
}
