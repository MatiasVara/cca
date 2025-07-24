// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Error as IoError;

#[derive(Debug)]
pub enum Error {
    VmCreate(IoError),
    GICCreate(IoError),
    GICInit(IoError),
    Config(IoError),
    RDCreate(IoError),
    RPopulate(IoError),
    RInitiate(IoError),
    RActivate(IoError),
}
