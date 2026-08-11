//! 协议配置由 common crate 统一定义，engine 仅保留内部重导出。

pub use protocol_simulation_common::{
    MailCredential, MailCustomResponse, MailMessage, SimDatabaseConfig, SimDnsConfig, SimFtpConfig,
    SimHttpConfig, SimImapConfig, SimLdapConfig, SimPop3Config, SimRdpConfig, SimRedisConfig,
    SimSmbConfig, SimSmtpConfig, SimSshConfig, SimTelnetConfig,
};
