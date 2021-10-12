package com.baidu.hugegraph.loader.source.jdbc.auth;

import com.baidu.hugegraph.loader.source.jdbc.JDBCSource;
import com.baidu.hugegraph.loader.source.jdbc.auth.util.LoginUtil;
import com.baidu.hugegraph.util.Log;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import java.util.Map;

public class KerberosLogin implements Authentication {
    public static final Logger LOG = Log.logger(KerberosLogin.class);
    private static final String HIVE_DRIVER = "org.apache.hive.jdbc.HiveDriver";

    private static final String ZOOKEEPER_DEFAULT_LOGIN_CONTEXT_NAME = "Client";
    private static final String ZOOKEEPER_SERVER_PRINCIPAL_KEY =
            "zookeeper.server.principal";

    private static Configuration CONF = null;
    private static String KRB5_FILE = null;
    private static String USER_NAME = null;
    private static String USER_KEYTAB_FILE = null;
    private static String zkQuorum = null;
    private static String auth = null;
    private static String sasl_qop = null;
    private static String zooKeeperNamespace = null;
    private static String serviceDiscoveryMode = null;
    private static String principal = null;

    @Override
    public String auth(JDBCSource source) throws Exception {
//        if (!MapUtils.isEmpty(source.getProperties())) {
//            for (Map.Entry<String, String> entry :
//                    source.getProperties().entrySet()) {
//                System.setProperty(entry.getKey(), entry.getValue());
//                LOG.info("property-{}:{}", entry.getKey(), entry.getValue());
//            }
//        }
        CONF = new Configuration();
        String zookeeperPrincipal = "zookeeper/hadoop";
        Map<String, String> clientInfo = source.getPrincipals();
        zkQuorum = clientInfo.get("zk.quorum");
        auth = clientInfo.get("auth");
        sasl_qop = clientInfo.get("sasl.qop");
        zooKeeperNamespace = clientInfo.get("zooKeeperNamespace");
        serviceDiscoveryMode = clientInfo.get("serviceDiscoveryMode");
        principal = clientInfo.get("principal");
        USER_NAME = clientInfo.get("user.name");
        String sslEnable = clientInfo.get("ssl");
        StringBuilder builder = new StringBuilder();
        if ("KERBEROS".equalsIgnoreCase(auth)) {
            try {
                USER_KEYTAB_FILE = clientInfo.get("user.keytab");
                KRB5_FILE = clientInfo.get("krb5.conf");
                System.setProperty("java.security.krb5.conf", KRB5_FILE);
                zookeeperPrincipal =  clientInfo.get("zookeeperPrincipal");
                if (StringUtils.isEmpty(zookeeperPrincipal)) {
                    zookeeperPrincipal = USER_NAME;
                }
                LoginUtil.setJaasConf(ZOOKEEPER_DEFAULT_LOGIN_CONTEXT_NAME,
                        USER_NAME, USER_KEYTAB_FILE);
                LoginUtil.setZookeeperServerPrincipal(
                        ZOOKEEPER_SERVER_PRINCIPAL_KEY,
                        zookeeperPrincipal);
                Configuration conf = new Configuration();
                //  conf.setBoolean("hadoop.security.authorization", true);
                  conf.set("hadoop.security.authentication", "kerberos");
                //  System.setProperty("sun.security.krb5.debug", "true");
//                String credsOnly = "false";
//                if (!StringUtils.isEmpty(clientInfo.get("credsOnly"))) {
//                    credsOnly = clientInfo.get("credsOnly");
//                }
//                System.setProperty("javax.security.auth.useSubjectCredsOnly",
//                        "false");
                UserGroupInformation.setConfiguration(conf);
                UserGroupInformation.loginUserFromKeytab(
                        USER_NAME,
                        USER_KEYTAB_FILE);
                LoginUtil.login(USER_NAME, USER_KEYTAB_FILE, KRB5_FILE, CONF);
            } catch (Exception e) {
                LOG.error(e.getMessage());
                throw e;
            }
            if (!StringUtils.isEmpty(sslEnable)) {
                builder.append(";ssl=")
                        .append(sslEnable);
            }
            builder.append(";serviceDiscoveryMode=")
                    .append(serviceDiscoveryMode)
                    .append(";zooKeeperNamespace=")
                    .append(zooKeeperNamespace);
            if (!StringUtils.isEmpty(sasl_qop)) {
                builder.append(";sasl.qop=")
                        .append(sasl_qop);
            }
            builder.append(";auth=")
                    .append(auth)
                    .append(";principal=")
                    .append(principal)
                    .append(";");
            LOG.info("builder:" + builder);
        } else {
            builder.append(";serviceDiscoveryMode=")
                    .append(serviceDiscoveryMode)
                    .append(";zooKeeperNamespace=")
                    .append(zooKeeperNamespace)
                    .append(";auth=none");
        }
        return builder.toString();

    }
}
