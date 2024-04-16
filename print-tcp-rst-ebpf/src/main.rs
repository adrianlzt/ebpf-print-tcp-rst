#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, EbpfContext};
use aya_log_ebpf::error;

// tcp:tcp_send_reset
//     const void * skbaddr;
//     const void * skaddr;
//     __u16 sport;
//     __u16 dport;
//     __u8 saddr[4];
//     __u8 daddr[4];
//     __u8 saddr_v6[16];
//     __u8 daddr_v6[16];
//
// name: tcp_send_reset
// ID: 1509
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:const void * skbaddr;     offset:8;       size:8; signed:0;
//         field:const void * skaddr;      offset:16;      size:8; signed:0;
//         field:int state;        offset:24;      size:4; signed:1;
//         field:__u16 sport;      offset:28;      size:2; signed:0;
//         field:__u16 dport;      offset:30;      size:2; signed:0;
//         field:__u16 family;     offset:32;      size:2; signed:0;
//         field:__u8 saddr[4];    offset:34;      size:4; signed:0;
//         field:__u8 daddr[4];    offset:38;      size:4; signed:0;
//         field:__u8 saddr_v6[16];        offset:42;      size:16;        signed:0;
//         field:__u8 daddr_v6[16];        offset:58;      size:16;        signed:0;

#[tracepoint(name = "tcp_send_reset", category = "tcp")]
pub fn tcp_send_reset(ctx: TracePointContext) -> i64 {
    match try_tcp_send_reset(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_send_reset(ctx: TracePointContext) -> Result<i64, i64> {
    // https://docs.rs/aya-ebpf/latest/aya_ebpf/programs/tracepoint/struct.TracePointContext.html#trait-implementations
    let pid: u32 = ctx.pid();

    // Return "unknown" if the command is not available
    // Command max length is 16 chars (including null terminator)
    let command = ctx.command().unwrap_or([
        'u' as u8, 'n' as u8, 'k' as u8, 'n' as u8, 'o' as u8, 'w' as u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
    ]);
    let command = unsafe { core::str::from_utf8_unchecked(&command) };

    const SPORT_OFFSET: usize = 28;
    let sport: u16 = unsafe { ctx.read_at(SPORT_OFFSET)? };

    const DPORT_OFFSET: usize = 30;
    let dport: u16 = unsafe { ctx.read_at(DPORT_OFFSET)? };

    error!(
        &ctx,
        "COMMAND={} PID={} SPORT={} DPORT={} tracepoint tcp:tcp_send_reset called",
        command,
        pid,
        sport,
        dport,
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
