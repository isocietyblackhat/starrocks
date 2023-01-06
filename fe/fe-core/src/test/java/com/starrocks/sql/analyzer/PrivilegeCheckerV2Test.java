// This file is licensed under the Elastic License 2.0. Copyright 2021-present, StarRocks Inc.

package com.starrocks.sql.analyzer;

import com.google.common.collect.Lists;
import com.starrocks.analysis.UserIdentity;
import com.starrocks.authentication.AuthenticationManager;
import com.starrocks.privilege.PrivilegeManager;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.DDLStmtExecutor;
import com.starrocks.sql.ast.CreateUserStmt;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.utframe.StarRocksAssert;
import com.starrocks.utframe.UtFrameUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.List;

public class PrivilegeCheckerV2Test {
    private static StarRocksAssert starRocksAssert;
    private static UserIdentity testUser;

    private static PrivilegeManager privilegeManager;

    @BeforeClass
    public static void beforeClass() throws Exception {
        UtFrameUtils.createMinStarRocksCluster();
        UtFrameUtils.addMockBackend(10002);
        UtFrameUtils.addMockBackend(10003);
        String createTblStmtStr = "create table db1.tbl1(k1 varchar(32), k2 varchar(32), k3 varchar(32), k4 int) "
                + "AGGREGATE KEY(k1, k2,k3,k4) distributed by hash(k1) buckets 3 properties('replication_num' = '1');";
        starRocksAssert = new StarRocksAssert(UtFrameUtils.initCtxForNewPrivilege(UserIdentity.ROOT));
        starRocksAssert.withDatabase("db1");
        starRocksAssert.withDatabase("db2");
        starRocksAssert.withTable(createTblStmtStr);
        privilegeManager = starRocksAssert.getCtx().getGlobalStateMgr().getPrivilegeManager();
        starRocksAssert.getCtx().setRemoteIP("localhost");
        privilegeManager.initBuiltinRolesAndUsers();
        ctxToRoot();
        createUsers();
    }

    private static void ctxToTestUser() {
        starRocksAssert.getCtx().setCurrentUserIdentity(testUser);
        starRocksAssert.getCtx().setQualifiedUser(testUser.getQualifiedUser());
    }

    private static void ctxToRoot() {
        starRocksAssert.getCtx().setCurrentUserIdentity(UserIdentity.ROOT);
        starRocksAssert.getCtx().setQualifiedUser(UserIdentity.ROOT.getQualifiedUser());
    }

    private static void createUsers() throws Exception {
        String createUserSql = "CREATE USER 'test' IDENTIFIED BY ''";
        CreateUserStmt createUserStmt =
                (CreateUserStmt) UtFrameUtils.parseStmtWithNewParser(createUserSql, starRocksAssert.getCtx());

        AuthenticationManager authenticationManager =
                starRocksAssert.getCtx().getGlobalStateMgr().getAuthenticationManager();
        authenticationManager.createUser(createUserStmt);
        testUser = createUserStmt.getUserIdent();

        createUserSql = "CREATE USER 'test2' IDENTIFIED BY ''";
        createUserStmt = (CreateUserStmt) UtFrameUtils.parseStmtWithNewParser(createUserSql, starRocksAssert.getCtx());
        authenticationManager.createUser(createUserStmt);

        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                "create role test_role", starRocksAssert.getCtx()), starRocksAssert.getCtx());
    }

    private static void verifyGrantRevoke(String sql, String grantSql, String revokeSql,
                                          String expectError) throws Exception {
        ConnectContext ctx = starRocksAssert.getCtx();
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(sql, starRocksAssert.getCtx());

        // 1. before grant: access denied
        ctxToTestUser();
        try {
            PrivilegeCheckerV2.check(statement, ctx);
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + sql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }

        ctxToRoot();
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(grantSql, ctx), ctx);

        ctxToTestUser();
        PrivilegeCheckerV2.check(statement, ctx);

        ctxToRoot();
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(revokeSql, ctx), ctx);

        ctxToTestUser();
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + sql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }
    }

    @Test
    public void testTableSelectDeleteInsert() throws Exception {
        verifyGrantRevoke(
                "select * from db1.tbl1",
                "grant select on db1.tbl1 to test",
                "revoke select on db1.tbl1 from test",
                "SELECT command denied to user 'test'");
        verifyGrantRevoke(
                "insert into db1.tbl1 values ('petals', 'on', 'a', 99);",
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'");
        verifyGrantRevoke(
                "delete from db1.tbl1 where k3 = 1",
                "grant delete on db1.tbl1 to test",
                "revoke delete on db1.tbl1 from test",
                "DELETE command denied to user 'test'");
    }

    @Test
    public void testTableCreateDrop() throws Exception {
        String createTableSql = "create table db1.tbl2(k1 varchar(32), k2 varchar(32), k3 varchar(32), k4 int) "
                + "AGGREGATE KEY(k1, k2,k3,k4) distributed by hash(k1) buckets 3 properties('replication_num' = '1');";
        verifyGrantRevoke(
                createTableSql,
                "grant create_table on database db1 to test",
                "revoke create_table on database db1 from test",
                "Access denied for user 'test' to database 'db1'");
        verifyGrantRevoke(
                "drop table db1.tbl1",
                "grant drop on db1.tbl1 to test",
                "revoke drop on db1.tbl1 from test",
                "DROP command denied to user 'test'");
    }

    @Test
    public void testGrantRevokePrivilege() throws Exception {
        verifyGrantRevoke(
                "grant select on db1.tbl1 to test",
                "grant select on db1.tbl1 to test with grant option",
                "revoke select on db1.tbl1 from test",
                "Access denied; you need (at least one of) the GRANT privilege(s) for this operation");
        verifyGrantRevoke(
                "revoke select on db1.tbl1 from test",
                "grant select on db1.tbl1 to test with grant option",
                "revoke select on db1.tbl1 from test with grant option",
                "Access denied; you need (at least one of) the GRANT privilege(s) for this operation");
    }

    @Test
    public void testResourceStmt() throws Exception {
        String createResourceStmt = "create external resource 'hive0' PROPERTIES(" +
                "\"type\"  =  \"hive\", \"hive.metastore.uris\"  =  \"thrift://127.0.0.1:9083\")";
        verifyGrantRevoke(
                createResourceStmt,
                "grant create_resource on system to test",
                "revoke create_resource on system from test",
                "Access denied; you need (at least one of) the CREATE_RESOURCE privilege(s) for this operation");
        starRocksAssert.withResource(createResourceStmt);

        verifyGrantRevoke(
                "alter RESOURCE hive0 SET PROPERTIES (\"hive.metastore.uris\" = \"thrift://10.10.44.91:9083\");",
                "grant alter on resource 'hive0' to test",
                "revoke alter on resource 'hive0' from test",
                "Access denied; you need (at least one of) the ALTER privilege(s) for this operation");

        verifyGrantRevoke(
                "drop resource hive0;",
                "grant drop on resource hive0 to test",
                "revoke drop on resource hive0 from test",
                "Access denied; you need (at least one of) the DROP privilege(s) for this operation");

        // on all
        verifyGrantRevoke(
                "drop resource hive0;",
                "grant drop on all resources to test",
                "revoke drop on all resources from test",
                "Access denied; you need (at least one of) the DROP privilege(s) for this operation");
    }

    @Test
    public void testViewStmt() throws Exception {
        ConnectContext ctx = starRocksAssert.getCtx();

        // grant select on base table to user
        String grantBaseTableSql = "grant select on db1.tbl1 to test";
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                grantBaseTableSql, ctx), ctx);

        // privilege check for create_view on database
        String createViewStmt = "create view db1.view1 as select * from db1.tbl1";
        String grantCreateViewStmt = "grant create_view on database db1 to test";
        String revokeCreateViewStmt = "revoke create_view on database db1 from test";
        verifyGrantRevoke(
                createViewStmt,
                grantCreateViewStmt,
                revokeCreateViewStmt,
                "Access denied for user 'test' to database 'db1'");

        // revoke select on base table, grant create_viw on database to user
        String revokeBaseTableSql = "revoke select on db1.tbl1 from test";
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                revokeBaseTableSql, ctx), ctx);
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                grantCreateViewStmt, ctx), ctx);
        verifyGrantRevoke(
                createViewStmt,
                grantBaseTableSql,
                revokeBaseTableSql,
                "SELECT command denied to user 'test'");

        // create the view
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(createViewStmt, ctx), ctx);

        // revoke create_view on database, grant select on base table to user
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                revokeCreateViewStmt, ctx), ctx);
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                grantBaseTableSql, ctx), ctx);
        String grantAlterSql = "grant alter on view db1.view1 to test";
        String revokeAlterSql = "revoke alter on view db1.view1 from test";
        String alterViewSql = "alter view db1.view1 as select k2, k3 from db1.tbl1";
        verifyGrantRevoke(
                alterViewSql,
                grantAlterSql,
                revokeAlterSql,
                "ALTER command denied to user 'test'");

        // revoke select on base table, grant alter on view to user
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                revokeBaseTableSql, ctx), ctx);
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                grantAlterSql, ctx), ctx);
        verifyGrantRevoke(
                alterViewSql,
                grantBaseTableSql,
                revokeBaseTableSql,
                "SELECT command denied to user 'test'");

        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                revokeAlterSql, ctx), ctx);

        // test select view
        String selectViewSql = "select * from db1.view1";
        verifyGrantRevoke(
                selectViewSql,
                grantBaseTableSql,
                revokeBaseTableSql,
                "SELECT command denied to user 'test'");
        verifyGrantRevoke(
                selectViewSql,
                "grant select on view db1.view1 to test",
                "revoke select on view db1.view1 from test",
                "SELECT command denied to user 'test'");

        // drop view
        verifyGrantRevoke(
                "drop view db1.view1",
                "grant drop on view db1.view1 to test",
                "revoke drop on view db1.view1 from test",
                "DROP command denied to user 'test'");
    }

    @Test
    public void testPluginStmts() throws Exception {
        String grantSql = "grant plugin on system to test";
        String revokeSql = "revoke plugin on system from test";
        String err = "Access denied; you need (at least one of) the PLUGIN privilege(s) for this operation";

        String sql = "INSTALL PLUGIN FROM \"/home/users/starrocks/auditdemo.zip\"";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "UNINSTALL PLUGIN auditdemo";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "SHOW PLUGINS";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
    }

    @Test
    public void testFileStmts() throws Exception {
        ConnectContext ctx = starRocksAssert.getCtx();
        ctx.setCurrentUserIdentity(UserIdentity.ROOT);
        String grantSelectTableSql = "grant select on db1.tbl1 to test";
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(grantSelectTableSql, ctx), ctx);

        // check file in system
        String createFileSql = "CREATE FILE \"client.key\" IN db1\n" +
                "PROPERTIES(\"catalog\" = \"internal\", \"url\" = \"http://test.bj.bcebos.com/kafka-key/client.key\")";
        String dropFileSql = "DROP FILE \"client.key\" FROM db1 PROPERTIES(\"catalog\" = \"internal\")";

        verifyGrantRevoke(
                createFileSql,
                "grant file on system to test",
                "revoke file on system from test",
                "Access denied; you need (at least one of) the FILE privilege(s) for this operation");
        verifyGrantRevoke(
                dropFileSql,
                "grant file on system to test",
                "revoke file on system from test",
                "Access denied; you need (at least one of) the FILE privilege(s) for this operation");

        ctx.setCurrentUserIdentity(UserIdentity.ROOT);
        String revokeSelectTableSql = "revoke select on db1.tbl1 from test";
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(revokeSelectTableSql, ctx), ctx);
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(
                "grant file on system to test", ctx), ctx);

        // check any action in table
        String dbDeniedError = "Access denied for user 'test' to database 'db1'";
        verifyGrantRevoke(createFileSql, grantSelectTableSql, revokeSelectTableSql, dbDeniedError);
        verifyGrantRevoke(dropFileSql, grantSelectTableSql, revokeSelectTableSql, dbDeniedError);
        verifyGrantRevoke("show file from db1", grantSelectTableSql, revokeSelectTableSql, dbDeniedError);

        // check any action in db
        String grantDropDbSql = "grant drop on database db1 to test";
        String revokeDropDbSql = "revoke drop on database db1 from test";
        verifyGrantRevoke(createFileSql, grantDropDbSql, revokeDropDbSql, dbDeniedError);
        verifyGrantRevoke(dropFileSql, grantDropDbSql, revokeDropDbSql, dbDeniedError);
        verifyGrantRevoke("show file from db1", grantDropDbSql, revokeDropDbSql, dbDeniedError);
    }

    @Test
    public void testBlackListStmts() throws Exception {
        String grantSql = "grant blacklist on system to test";
        String revokeSql = "revoke blacklist on system from test";
        String err = "Access denied; you need (at least one of) the BLACKLIST privilege(s) for this operation";

        String sql = "ADD SQLBLACKLIST \"select count\\\\(\\\\*\\\\) from .+\";";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "DELETE SQLBLACKLIST 0";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "SHOW SQLBLACKLIST";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
    }

    @Test
    public void testRoleUserStmts() throws Exception {
        String grantSql = "grant user_admin to test";
        String revokeSql = "revoke user_admin from test";
        String err = "Access denied; you need (at least one of) the GRANT privilege(s) for this operation";
        String sql;

        sql = "grant test_role to test";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "revoke test_role from test";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "create user tesssst";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "drop user test";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "alter user test identified by 'asdf'";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "show roles";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "create role testrole2";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);

        sql = "drop role test_role";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
    }

    @Test
    public void testShowPrivsForOther() throws Exception {
        String grantSql = "grant user_admin to test";
        String revokeSql = "revoke user_admin from test";
        String err = "Access denied; you need (at least one of) the GRANT privilege(s) for this operation";
        String sql;

        ConnectContext ctx = starRocksAssert.getCtx();

        sql = "show grants for test2";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
        ctxToTestUser();
        PrivilegeCheckerV2.check(UtFrameUtils.parseStmtWithNewParser("show grants", ctx), ctx);

        sql = "show authentication for test2";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
        ctxToTestUser();
        PrivilegeCheckerV2.check(UtFrameUtils.parseStmtWithNewParser("show authentication", ctx), ctx);

        sql = "SHOW PROPERTY FOR 'test2'";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
        ctxToTestUser();
        PrivilegeCheckerV2.check(UtFrameUtils.parseStmtWithNewParser("show property", ctx), ctx);

        sql = "set property for 'test2' 'max_user_connections' = '100'";
        verifyGrantRevoke(sql, grantSql, revokeSql, err);
        ctxToTestUser();
        PrivilegeCheckerV2.check(UtFrameUtils.parseStmtWithNewParser(
                "set property 'max_user_connections' = '100'", ctx), ctx);
    }

    @Test
    public void testExecuteAs() throws Exception {
        verifyGrantRevoke(
                "EXECUTE AS test2 WITH NO REVERT",
                "grant impersonate on user test2 to test",
                "revoke impersonate on user test2 from test",
                "Access denied; you need (at least one of) the IMPERSONATE privilege(s) for this operation");
    }

    @Test
    public void testDatabaseStmt() throws Exception {
        final String testDbName = "db_for_db_stmt_test";
        starRocksAssert.withDatabase(testDbName);
        String createTblStmtStr = "create table " + testDbName +
                ".tbl1(k1 varchar(32), k2 varchar(32), k3 varchar(32), k4 int) " +
                "AGGREGATE KEY(k1, k2,k3,k4) distributed by hash(k1) buckets 3 properties('replication_num' = '1');";
        starRocksAssert.withTable(createTblStmtStr);

        List<String> statements = Lists.newArrayList();
        statements.add("use " + testDbName + ";");
        statements.add("show create database " + testDbName + ";");
        for (String stmt : statements) {
            // Test `use database` | `show create database xxx`: check any privilege on db
            verifyGrantRevoke(
                    stmt,
                    "grant DROP on database " + testDbName + " to test",
                    "revoke DROP on database " + testDbName + " from test",
                    "Access denied for user 'test' to database '" + testDbName + "'");
            verifyGrantRevoke(
                    stmt,
                    "grant CREATE_FUNCTION on database " + testDbName + " to test",
                    "revoke CREATE_FUNCTION on database " + testDbName + " from test",
                    "Access denied for user 'test' to database '" + testDbName + "'");
            verifyGrantRevoke(
                    stmt,
                    "grant ALTER on database " + testDbName + " to test",
                    "revoke ALTER on database " + testDbName + " from test",
                    "Access denied for user 'test' to database '" + testDbName + "'");
        }

        // Test `use database` : check any privilege on tables under db
        verifyGrantRevoke(
                "use " + testDbName + ";",
                "grant select on " + testDbName + ".tbl1 to test",
                "revoke select on " + testDbName + ".tbl1 from test",
                "Access denied for user 'test' to database '" + testDbName + "'");

        // Test `recover database xxx`: check DROP on db and CREATE_DATABASE on internal catalog
        // TODO(yiming): check for CREATE_DATABASE on internal catalog after catalog is added
        verifyGrantRevoke(
                "recover database " + testDbName + ";",
                "grant DROP on database " + testDbName + " to test",
                "revoke DROP on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");

        // Test `alter database xxx set...`: check ALTER on db
        verifyGrantRevoke(
                "alter database " + testDbName + " set data quota 10T;",
                "grant ALTER on database " + testDbName + " to test",
                "revoke ALTER on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");
        verifyGrantRevoke(
                "alter database " + testDbName + " set replica quota 102400;",
                "grant ALTER on database " + testDbName + " to test",
                "revoke ALTER on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");

        // Test `drop database xxx...`: check DROP on db
        verifyGrantRevoke(
                "drop database " + testDbName + ";",
                "grant DROP on database " + testDbName + " to test",
                "revoke DROP on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");
        verifyGrantRevoke(
                "drop database if exists " + testDbName + " force;",
                "grant DROP on database " + testDbName + " to test",
                "revoke DROP on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");

        // Test `alter database xxx rename xxx_new`: check ALTER on db
        verifyGrantRevoke(
                "alter database " + testDbName + " rename new_db_name;",
                "grant ALTER on database " + testDbName + " to test",
                "revoke ALTER on database " + testDbName + " from test",
                "Access denied for user 'test' to database '" + testDbName + "'");
    }
<<<<<<< HEAD
=======

    @Test
    public void testShowNodeStmt() throws Exception {
        verifyGrantRevoke(
                "show backends",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyNODEAndGRANT(
                "show backends",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyGrantRevoke(
                "show frontends",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyNODEAndGRANT(
                "show frontends",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyGrantRevoke(
                "show broker",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyNODEAndGRANT(
                "show broker",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyGrantRevoke(
                "show compute nodes",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

        verifyNODEAndGRANT(
                "show compute nodes",
                "Access denied; you need (at least one of) the OPERATE/NODE privilege(s) for this operation");

    }

    @Test
    public void testShowTabletStmt() throws Exception {
        verifyGrantRevoke(
                "show tablet from example_db.example_table",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");
    }

    @Test
    public void testShowTransactionStmt() throws Exception {
        ctxToTestUser();
        ConnectContext ctx = starRocksAssert.getCtx();
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser("SHOW TRANSACTION FROM db WHERE ID=4005;", ctx);
        PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
    }

    @Test
    public void testAdminOperateStmt() throws Exception {
        // AdminSetConfigStmt
        verifyGrantRevoke(
                "admin set frontend config (\"key\" = \"value\");",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminSetReplicaStatusStmt
        verifyGrantRevoke(
                "ADMIN SET REPLICA STATUS PROPERTIES(\"tablet_id\" = \"10003\", " +
                        "\"backend_id\" = \"10001\", \"status\" = \"bad\");",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminShowConfigStmt
        verifyGrantRevoke(
                "ADMIN SHOW FRONTEND CONFIG;",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminShowReplicaDistributionStatement
        verifyGrantRevoke(
                "ADMIN SHOW REPLICA DISTRIBUTION FROM example_db.example_table PARTITION(p1, p2);",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminShowReplicaStatusStatement
        verifyGrantRevoke(
                "ADMIN SHOW REPLICA STATUS FROM example_db.example_table;",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminRepairTableStatement
        verifyGrantRevoke(
                "ADMIN REPAIR TABLE example_db.example_table PARTITION(p1);",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminCancelRepairTableStatement
        verifyGrantRevoke(
                "ADMIN CANCEL REPAIR TABLE example_db.example_table PARTITION(p1);",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");

        // AdminCheckTabletsStatement
        verifyGrantRevoke(
                "ADMIN CHECK TABLET (1, 2) PROPERTIES (\"type\" = \"CONSISTENCY\");",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");
    }

    @Test
    public void testAlterSystemStmt() throws Exception {
        // AlterSystemStmt
        verifyNODEAndGRANT("ALTER SYSTEM ADD FOLLOWER \"127.0.0.1:9010\";",
                "Access denied; you need (at least one of) the NODE privilege(s) for this operation");

        // CancelAlterSystemStmt
        verifyNODEAndGRANT("CANCEL DECOMMISSION BACKEND \"127.0.0.1:9010\", \"127.0.0.1:9011\";",
                "Access denied; you need (at least one of) the NODE privilege(s) for this operation");
    }

    @Test
    public void testKillStmt() throws Exception {
        // KillStmt
        verifyGrantRevoke(
                "kill query 1",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");
    }

    @Test
    public void testShowProcStmt() throws Exception {
        // ShowProcStmt
        verifyGrantRevoke(
                "show proc '/backends'",
                "grant OPERATE on system to test",
                "revoke OPERATE on system from test",
                "Access denied; you need (at least one of) the OPERATE privilege(s) for this operation");
    }

    @Test
    public void testSetStmt() throws Exception {
        String sql = "SET PASSWORD FOR 'jack'@'192.%' = PASSWORD('123456');";
        String expectError = "Access denied; you need (at least one of) the GRANT privilege(s) for this operation";
        verifyNODEAndGRANT(sql, expectError);
    }

    @Test
    public void testRoutineLoadStmt() throws Exception {
        // CREATE ROUTINE LOAD STMT
        String createSql = "CREATE ROUTINE LOAD db1.job_name2 ON tbl1 " +
                "COLUMNS(c1) FROM KAFKA " +
                "( 'kafka_broker_list' = 'broker1:9092', 'kafka_topic' = 'my_topic', " +
                " 'kafka_partitions' = '0,1,2', 'kafka_offsets' = '0,0,0');";
        verifyGrantRevoke(
                createSql,
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");

        // ALTER ROUTINE LOAD STMT
        new MockUp<KafkaUtil>() {
            @Mock
            public List<Integer> getAllKafkaPartitions(String brokerList, String topic,
                                                       ImmutableMap<String, String> properties) {
                return Lists.newArrayList(0, 1, 2);
            }
        };
        String alterSql = "ALTER ROUTINE LOAD FOR db1.job_name2 PROPERTIES ( 'desired_concurrent_number' = '1')";
        ConnectContext ctx = starRocksAssert.getCtx();
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(alterSql, starRocksAssert.getCtx());
        try {
            PrivilegeCheckerV2.check(statement, ctx);
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + alterSql);
            Assert.assertTrue(
                    e.getMessage().contains("Routine load job [job_name2] not found when checking privilege"));
        }
        ctxToRoot();
        starRocksAssert.withRoutineLoad(createSql);
        ctxToTestUser();
        verifyGrantRevoke(
                "ALTER ROUTINE LOAD FOR db1.job_name1 PROPERTIES ( 'desired_concurrent_number' = '1');",
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");

        // STOP ROUTINE LOAD STMT
        verifyGrantRevoke(
                "STOP ROUTINE LOAD FOR db1.job_name1;",
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");

        // RESUME ROUTINE LOAD STMT
        verifyGrantRevoke(
                "RESUME ROUTINE LOAD FOR db1.job_name1;",
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");

        // PAUSE ROUTINE LOAD STMT
        verifyGrantRevoke(
                "PAUSE ROUTINE LOAD FOR db1.job_name1;",
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");

        // SHOW ROUTINE LOAD stmt;
        String showRoutineLoadSql = "SHOW ROUTINE LOAD FOR db1.job_name1;";
        statement = UtFrameUtils.parseStmtWithNewParser(showRoutineLoadSql, starRocksAssert.getCtx());
        PrivilegeCheckerV2.check(statement, ctx);

        // SHOW ROUTINE LOAD TASK FROM DB
        String showRoutineLoadTaskSql = "SHOW ROUTINE LOAD TASK FROM db1 WHERE JobName = 'job_name1';";
        statement = UtFrameUtils.parseStmtWithNewParser(showRoutineLoadTaskSql, starRocksAssert.getCtx());
        PrivilegeCheckerV2.check(statement, ctx);
    }

    @Test
    public void testRoutineLoadShowStmt() throws Exception {
        ctxToRoot();
        String createSql = "CREATE ROUTINE LOAD db1.job_name1 ON tbl1 " +
                "COLUMNS(c1) FROM KAFKA " +
                "( 'kafka_broker_list' = 'broker1:9092', 'kafka_topic' = 'my_topic', " +
                " 'kafka_partitions' = '0,1,2', 'kafka_offsets' = '0,0,0');";
        new MockUp<KafkaUtil>() {
            @Mock
            public List<Integer> getAllKafkaPartitions(String brokerList, String topic,
                                                       ImmutableMap<String, String> properties) {
                return Lists.newArrayList(0, 1, 2);
            }
        };
        starRocksAssert.withRoutineLoad(createSql);

        String showRoutineLoadTaskSql = "SHOW ROUTINE LOAD TASK FROM db1 WHERE JobName = 'job_name1';";
        StatementBase statementTask =
                UtFrameUtils.parseStmtWithNewParser(showRoutineLoadTaskSql, starRocksAssert.getCtx());
        ShowExecutor executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) statementTask);
        ShowResultSet set = executor.execute();
        for (int i = 0; i < 30; i++) {
            set = executor.execute();
            if (set.getResultRows().size() > 0) {
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        Assert.assertTrue(set.getResultRows().size() > 0);

        ctxToTestUser();
        // SHOW ROUTINE LOAD TASK
        ShowExecutor executorBeforeGrant = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) statementTask);
        set = executorBeforeGrant.execute();
        Assert.assertEquals(0, set.getResultRows().size());
        ctxToRoot();
        DDLStmtExecutor.execute(
                UtFrameUtils.parseStmtWithNewParser("grant insert on db1.tbl1 to test", starRocksAssert.getCtx()),
                starRocksAssert.getCtx());
        ctxToTestUser();
        ShowExecutor executorAfterGrant = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) statementTask);
        set = executorAfterGrant.execute();
        Assert.assertTrue(set.getResultRows().size() > 0);
        ctxToRoot();
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser("revoke insert on db1.tbl1 from test",
                        starRocksAssert.getCtx()),
                starRocksAssert.getCtx());
        ctxToTestUser();
    }

    @Test
    public void testLoadStmt() throws Exception {
        // LOAD STMT
        // create resource
        String createResourceStmt = "CREATE EXTERNAL RESOURCE \"my_spark\"" +
                "PROPERTIES (" +
                "\"type\" = \"spark\"," +
                "\"spark.master\" = \"yarn\", " +
                "\"spark.submit.deployMode\" = \"cluster\", " +
                "\"spark.executor.memory\" = \"1g\", " +
                "\"spark.yarn.queue\" = \"queue0\", " +
                "\"spark.hadoop.yarn.resourcemanager.address\" = \"resourcemanager_host:8032\", " +
                "\"spark.hadoop.fs.defaultFS\" = \"hdfs://namenode_host:9000\", " +
                "\"working_dir\" = \"hdfs://namenode_host:9000/tmp/starrocks\", " +
                "\"broker\" = \"broker0\", " +
                "\"broker.username\" = \"user0\", " +
                "\"broker.password\" = \"password0\"" +
                ");";
        starRocksAssert.withResource(createResourceStmt);
        // create load & check resource privilege
        String createSql = "LOAD LABEL db1.job_name1" +
                "(DATA INFILE('hdfs://test:8080/user/starrocks/data/input/example1.csv') " +
                "INTO TABLE tbl1) " +
                "WITH RESOURCE 'my_spark'" +
                "('username' = 'test_name','password' = 'pwd') " +
                "PROPERTIES ('timeout' = '3600');";
        ctxToRoot();
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(createSql, starRocksAssert.getCtx());
        ctxToTestUser();
        ConnectContext ctx = starRocksAssert.getCtx();
        try {
            PrivilegeCheckerV2.check(statement, ctx);
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + createSql);
            Assert.assertTrue(e.getMessage().contains(
                    "Access denied; you need (at least one of) the USAGE privilege(s) for this operation"
            ));
        }
        // create load & check table privilege
        createSql = "LOAD LABEL db1.job_name1" +
                "(DATA INFILE('hdfs://test:8080/user/starrocks/data/input/example1.csv') " +
                "INTO TABLE tbl1) " +
                "WITH BROKER 'my_broker'" +
                "('username' = 'test_name','password' = 'pwd') " +
                "PROPERTIES ('timeout' = '3600');";
        verifyGrantRevoke(
                createSql,
                "grant insert on db1.tbl1 to test",
                "revoke insert on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table '[tbl1]'");

        // create broker load
        createSql = "LOAD LABEL db1.job_name1" +
                "(DATA INFILE('hdfs://test:8080/user/starrocks/data/input/example1.csv') " +
                "INTO TABLE tbl1) " +
                "WITH RESOURCE 'my_spark'" +
                "('username' = 'test_name','password' = 'pwd') " +
                "PROPERTIES ('timeout' = '3600');";
        ctxToRoot();
        starRocksAssert.withLoad(createSql);
        ctxToTestUser();

        // ALTER LOAD STMT
        String alterLoadSql = "ALTER LOAD FOR db1.job_name1 PROPERTIES ('priority' = 'LOW');";
        checkOperateLoad(alterLoadSql);

        // CANCEL LOAD STMT
        ctxToRoot();
        String revokeResource = "revoke USAGE on resource 'my_spark' from test;";
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser(revokeResource, ctx), ctx);
        ctxToTestUser();
        String cancelLoadSql = "CANCEL LOAD FROM db1 WHERE LABEL = 'job_name1'";
        checkOperateLoad(cancelLoadSql);

        // SHOW LOAD STMT
        String showLoadSql = "SHOW LOAD FROM db1";
        statement = UtFrameUtils.parseStmtWithNewParser(showLoadSql, starRocksAssert.getCtx());
        PrivilegeCheckerV2.check(statement, ctx);
    }

    @Test
    public void testShowExportAndCancelExportStmt() throws Exception {

        ctxToRoot();
        // prepare
        mockBroker();
        String createExportSql = "EXPORT TABLE db1.tbl1 " +
                "TO 'hdfs://hdfs_host:port/a/b/c/' " +
                "WITH BROKER 'broker0'";
        starRocksAssert.withExport(createExportSql);
        String showExportSql = "SHOW EXPORT FROM db1";
        StatementBase showExportSqlStmt = UtFrameUtils.parseStmtWithNewParser(showExportSql, starRocksAssert.getCtx());
        ShowExecutor executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        ShowResultSet set = executor.execute();
        for (int i = 0; i < 30; i++) {
            set = executor.execute();
            if (set.getResultRows().size() > 0) {
                break;
            } else {
                Thread.sleep(1000);
            }
        }
        Assert.assertTrue(set.getResultRows().size() > 0);

        // SHOW EXPORT STMT
        ctxToTestUser();
        showExportSqlStmt = UtFrameUtils.parseStmtWithNewParser(showExportSql, starRocksAssert.getCtx());
        ShowExecutor executorBeforeGrant = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        set = executorBeforeGrant.execute();
        Assert.assertEquals(0, set.getResultRows().size());
        DDLStmtExecutor.execute(
                UtFrameUtils.parseStmtWithNewParser("grant insert on db1.tbl1 to test", starRocksAssert.getCtx()),
                starRocksAssert.getCtx());
        ctxToTestUser();
        ShowExecutor executorAfterGrant = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        set = executorAfterGrant.execute();
        Assert.assertTrue(set.getResultRows().size() > 0);
        ctxToRoot();
        DDLStmtExecutor.execute(UtFrameUtils.parseStmtWithNewParser("revoke insert on db1.tbl1 from test",
                        starRocksAssert.getCtx()),
                starRocksAssert.getCtx());
        ctxToTestUser();

        // CANCEL EXPORT STMT
        String queryId = set.getResultRows().get(0).get(1);
        String cancelExportSql = "CANCEL EXPORT from db1 WHERE queryid = '" + queryId + "';";
        String expectError = "Access denied; you need (at least one of) the EXPORT privilege(s) for this operation";
        verifyGrantRevoke(
                cancelExportSql,
                "grant export on db1.tbl1 to test",
                "revoke export on db1.tbl1 from test",
                expectError);
    }

    @Test
    public void testExportStmt() throws Exception {

        mockBroker();
        String createExportSql = "EXPORT TABLE db1.tbl1 " +
                "TO 'hdfs://hdfs_host:port/a/b/c/' " +
                "WITH BROKER 'broker0'";
        String expectError = "Access denied; you need (at least one of) the EXPORT privilege(s) for this operation";
        verifyGrantRevoke(
                createExportSql,
                "grant export on db1.tbl1 to test",
                "revoke export on db1.tbl1 from test",
                expectError);
    }

    @Test
    public void testRepositoryStmt() throws Exception {
        mockBroker();
        String expectError = "Access denied; you need (at least one of) the REPOSITORY privilege(s) for this operation";

        String createRepoSql = "CREATE REPOSITORY `oss_repo` WITH BROKER `broker0` " +
                "ON LOCATION 'oss://starRocks_backup' PROPERTIES ( " +
                "'fs.oss.accessKeyId' = 'xxx'," +
                "'fs.oss.accessKeySecret' = 'yyy'," +
                "'fs.oss.endpoint' = 'oss-cn-beijing.aliyuncs.com');";
        // CREATE REPOSITORY STMT
        verifyGrantRevoke(
                createRepoSql,
                "grant repository on system to test",
                "revoke repository on system from test",
                expectError);

        mockRepository();

        // DROP REPOSITORY STMT
        verifyGrantRevoke(
                "DROP REPOSITORY `repo_name`;",
                "grant repository on system to test",
                "revoke repository on system from test",
                expectError);

        // SHOW SNAPSHOT STMT
        verifyGrantRevoke(
                "SHOW SNAPSHOT ON oss_repo;",
                "grant repository on system to test",
                "revoke repository on system from test",
                expectError);
    }

    @Test
    public void testBackupStmt() throws Exception {
        mockRepository();
        String expectError = "Access denied; you need (at least one of) the REPOSITORY privilege(s) for this operation";
        String createBackupSql = "BACKUP SNAPSHOT db1.backup_name1 " +
                "TO example_repo " +
                "ON (tbl1) " +
                "PROPERTIES ('type' = 'full');";

        // check REPOSITORY privilege
        ctxToTestUser();
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(createBackupSql,
                starRocksAssert.getCtx());
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + createBackupSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }

        ctxToRoot();
        grantOrRevoke("grant repository on system to test");
        // check EXPORT privilege
        ctxToTestUser();
        expectError = "EXPORT command denied to user 'test'@'localhost' for table 'tbl1'";
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + createBackupSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }

        ctxToRoot();
        grantOrRevoke("grant export on db1.tbl1 to test");
        // has all privilege
        ctxToTestUser();
        PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
        // revoke all privilege
        ctxToRoot();
        grantOrRevoke("revoke repository on system from test");
        grantOrRevoke("revoke export on db1.tbl1 from test");
        ctxToTestUser();
    }

    @Test
    public void testShowBackupStmtInShowExecutor() throws Exception {

        mockAddBackupJob("db1");
        ctxToTestUser();
        String showBackupSql = "SHOW BACKUP FROM db1;";
        StatementBase showExportSqlStmt = UtFrameUtils.parseStmtWithNewParser(showBackupSql, starRocksAssert.getCtx());
        ShowExecutor executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        ShowResultSet set = executor.execute();
        Assert.assertEquals(0, set.getResultRows().size());
        ctxToRoot();
        grantOrRevoke("grant export on db1.tbl1 to test");
        // user(test) has all privilege
        ctxToTestUser();
        executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        set = executor.execute();
        Assert.assertTrue(set.getResultRows().size() > 0);
        // revoke all privilege
        ctxToRoot();
        grantOrRevoke("revoke export on db1.tbl1 from test");
        ctxToTestUser();
    }

    @Test
    public void testShowBackupStmtInChecker() throws Exception {
        String expectError = "Access denied; you need (at least one of) the REPOSITORY privilege(s) for this operation";
        verifyGrantRevoke(
                "SHOW BACKUP FROM db1;",
                "grant repository on system to test",
                "revoke repository on system from test",
                expectError);
    }

    @Test
    public void testCancelBackupStmt() throws Exception {
        mockAddBackupJob("db2");
        ctxToRoot();
        grantOrRevoke("grant repository on system to test");
        ctxToTestUser();
        String cancelBackupSql = "CANCEL BACKUP FROM db2;";
        verifyGrantRevoke(cancelBackupSql,
                "grant export on db2.tbl1 to test",
                "revoke export on db2.tbl1 from test",
                "EXPORT command denied to user 'test'@'localhost' for table 'tbl1'");
        ctxToRoot();
        grantOrRevoke("revoke repository on system from test");
    }

    @Test
    public void testRestoreStmt() throws Exception {

        ctxToTestUser();
        String restoreSql = "RESTORE SNAPSHOT db1.`snapshot_1` FROM `example_repo` " +
                "ON ( `tbl1` ) " +
                "PROPERTIES ( 'backup_timestamp' = '2018-05-04-16-45-08', 'replication_num' = '1');";

        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(restoreSql, starRocksAssert.getCtx());

        ctxToTestUser();
        String expectError = "Access denied; you need (at least one of) the REPOSITORY privilege(s) for this operation";
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + restoreSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }
        ctxToRoot();
        grantOrRevoke("grant repository on system to test");
        ctxToTestUser();
        expectError = "Access denied for user 'test' to database 'db1'";
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + restoreSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }
        ctxToRoot();
        grantOrRevoke("grant create_view on database db1 to test");

        verifyGrantRevoke(restoreSql,
                "grant SELECT,INSERT on db1.tbl1 to test",
                "revoke SELECT,INSERT on db1.tbl1 from test",
                "INSERT command denied to user 'test'@'localhost' for table 'tbl1'");
        // revoke
        ctxToRoot();
        grantOrRevoke("revoke repository on system from test");
        grantOrRevoke("revoke all on database db1 from test");
    }

    @Test
    public void testCreateMaterializedViewStatement() throws Exception {

        Config.enable_experimental_mv = true;
        String createSql = "create materialized view db1.mv1 " +
                "distributed by hash(k2)" +
                "refresh async START('9999-12-31') EVERY(INTERVAL 3 SECOND) " +
                "PROPERTIES (\n" +
                "\"replication_num\" = \"1\"\n" +
                ") " +
                "as select k1, db1.tbl1.k2 from db1.tbl1;";

        String expectError = "Access denied; you need (at least one of) the " +
                "CREATE MATERIALIZED VIEW privilege(s) for this operation";
        verifyGrantRevoke(
                createSql,
                "grant create_materialized_view on db1 to test",
                "revoke create_materialized_view on db1 from test",
                expectError);
    }

    @Test
    public void testAlterMaterializedViewStatement() throws Exception {

        Config.enable_experimental_mv = true;
        String createSql = "create materialized view db1.mv1 " +
                "distributed by hash(k2)" +
                "refresh async START('9999-12-31') EVERY(INTERVAL 3 SECOND) " +
                "PROPERTIES (\n" +
                "\"replication_num\" = \"1\"\n" +
                ") " +
                "as select k1, db1.tbl1.k2 from db1.tbl1;";
        starRocksAssert.withMaterializedStatementView(createSql);
        verifyGrantRevoke(
                "alter materialized view db1.mv1 rename mv2;",
                "grant alter on materialized_view db1.mv1 to test",
                "revoke alter on materialized_view db1.mv1 from test",
                "Access denied; you need (at least one of) the ALTER " +
                        "MATERIALIZED VIEW privilege(s) for this operation");
        ctxToRoot();
        starRocksAssert.dropMaterializedView("db1.mv1");
        ctxToTestUser();
    }

    @Test
    public void testRefreshMaterializedViewStatement() throws Exception {

        ctxToRoot();
        Config.enable_experimental_mv = true;
        String createSql = "create materialized view db1.mv2 " +
                "distributed by hash(k2)" +
                "refresh async START('9999-12-31') EVERY(INTERVAL 3 SECOND) " +
                "PROPERTIES (\n" +
                "\"replication_num\" = \"1\"\n" +
                ") " +
                "as select k1, db1.tbl1.k2 from db1.tbl1;";
        starRocksAssert.withMaterializedStatementView(createSql);
        verifyGrantRevoke(
                "REFRESH MATERIALIZED VIEW db1.mv2;",
                "grant refresh on materialized_view db1.mv2 to test",
                "revoke refresh on materialized_view db1.mv2 from test",
                "Access denied; you need (at least one of) the REFRESH MATETIALIZED VIEW privilege(s) for this operation");
        verifyGrantRevoke(
                "CANCEL REFRESH MATERIALIZED VIEW db1.mv2;",
                "grant refresh on materialized_view db1.mv2 to test",
                "revoke refresh on materialized_view db1.mv2 from test",
                "Access denied; you need (at least one of) the REFRESH MATETIALIZED VIEW privilege(s) for this operation");

        ctxToRoot();
        starRocksAssert.dropMaterializedView("db1.mv2");
        ctxToTestUser();
    }

    @Test
    public void testShowMaterializedViewStatement() throws Exception {
        ctxToRoot();
        Config.enable_experimental_mv = true;
        String createSql = "create materialized view db1.mv3 " +
                "distributed by hash(k2)" +
                "refresh async START('9999-12-31') EVERY(INTERVAL 3 SECOND) " +
                "PROPERTIES (\n" +
                "\"replication_num\" = \"1\"\n" +
                ") " +
                "as select k1, db1.tbl1.k2 from db1.tbl1;";
        starRocksAssert.withMaterializedStatementView(createSql);
        String showBackupSql = "SHOW MATERIALIZED VIEW FROM db1;";
        StatementBase showExportSqlStmt = UtFrameUtils.parseStmtWithNewParser(showBackupSql, starRocksAssert.getCtx());
        ShowExecutor executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        ShowResultSet set = executor.execute();
        Assert.assertTrue(set.getResultRows().size() > 0);
        grantOrRevoke("grant SELECT,INSERT on db1.tbl1 to test");
        ctxToTestUser();
        executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        set = executor.execute();
        Assert.assertEquals(0, set.getResultRows().size());
        ctxToRoot();
        grantOrRevoke("grant refresh on materialized_view db1.mv3 to test");
        ctxToTestUser();
        executor = new ShowExecutor(starRocksAssert.getCtx(), (ShowStmt) showExportSqlStmt);
        set = executor.execute();
        Assert.assertTrue(set.getResultRows().size() > 0);
        ctxToRoot();
        grantOrRevoke("revoke SELECT,INSERT on db1.tbl1 from test");
        grantOrRevoke("revoke refresh on materialized_view db1.mv3 from test");
        starRocksAssert.dropMaterializedView("db1.mv3");
        ctxToTestUser();
    }

    @Test
    public void testDropMaterializedViewStatement() throws Exception {

        ctxToRoot();
        Config.enable_experimental_mv = true;
        String createSql = "create materialized view db1.mv4 " +
                "distributed by hash(k2)" +
                "refresh async START('9999-12-31') EVERY(INTERVAL 3 SECOND) " +
                "PROPERTIES (\n" +
                "\"replication_num\" = \"1\"\n" +
                ") " +
                "as select k1, db1.tbl1.k2 from db1.tbl1;";
        starRocksAssert.withMaterializedStatementView(createSql);
        verifyGrantRevoke(
                "DROP MATERIALIZED VIEW db1.mv4;",
                "grant drop on materialized_view db1.mv4 to test",
                "revoke drop on materialized_view db1.mv4 from test",
                "Access denied; you need (at least one of) the DROP MATETIALIZED VIEW privilege(s) for this operation");

        ctxToRoot();
        starRocksAssert.dropMaterializedView("db1.mv4");
        ctxToTestUser();
    }

    @Test
    public void testCreateFunc() throws Exception {

        new MockUp<CreateFunctionStmt>() {
            @Mock
            public void analyze(ConnectContext context) throws AnalysisException {
            }
        };

        String createSql = "CREATE FUNCTION db1.MY_UDF_JSON_GET(string, string) RETURNS string " +
                "properties ( " +
                "'symbol' = 'com.starrocks.udf.sample.UDFSplit', 'object_file' = 'test' " +
                ")";
        String expectError = "Access denied; you need (at least one of) the " +
                "CREATE FUNCTION privilege(s) for this operation";
        verifyGrantRevoke(
                createSql,
                "grant create_function on db1 to test",
                "revoke create_function on db1 from test",
                expectError);
    }

    @Test
    public void testCreateGlobalFunc() throws Exception {

        new MockUp<CreateFunctionStmt>() {
            @Mock
            public void analyze(ConnectContext context) throws AnalysisException {
            }
        };

        String createSql = "CREATE GLOBAL FUNCTION MY_UDF_JSON_GET(string, string) RETURNS string " +
                "properties ( " +
                "'symbol' = 'com.starrocks.udf.sample.UDFSplit', 'object_file' = 'test' " +
                ")";
        String expectError = "Access denied; you need (at least one of) the " +
                "CREATE_GLOBAL_FUNCTION privilege(s) for this operation";
        verifyGrantRevoke(
                createSql,
                "grant create_global_function on system to test",
                "revoke create_global_function on system from test",
                expectError);
    }

    @Test
    public void testDropFunc() throws Exception {

        Database db1 = GlobalStateMgr.getCurrentState().getDb("db1");
        FunctionName fn = FunctionName.createFnName("db1.my_udf_json_get");
        Function function = new Function(fn, Arrays.asList(Type.STRING, Type.STRING), Type.STRING, false);
        try {
            db1.addFunction(function);
        } catch (Throwable e) {
            // ignore
        }

        verifyGrantRevoke(
                "DROP FUNCTION db1.MY_UDF_JSON_GET(string, string);",
                "grant drop on ALL FUNCTIONS in database db1 to test",
                "revoke drop on ALL FUNCTIONS in database db1 from test",
                "Access denied; you need (at least one of) the DROP FUNCTION privilege(s) for this operation");

        verifyGrantRevoke(
                "DROP FUNCTION db1.MY_UDF_JSON_GET(string, string);",
                "grant drop on FUNCTION db1.MY_UDF_JSON_GET(string, string) to test",
                "revoke drop on FUNCTION db1.MY_UDF_JSON_GET(string, string) from test",
                "Access denied; you need (at least one of) the DROP FUNCTION privilege(s) for this operation");
    }

    @Test
    public void testDropGlobalFunc() throws Exception {

        FunctionName fn = FunctionName.createFnName("my_udf_json_get");
        fn.setAsGlobalFunction();
        Function function = new Function(fn, Arrays.asList(Type.STRING, Type.STRING), Type.STRING, false);
        try {
            GlobalStateMgr.getCurrentState().getGlobalFunctionMgr().replayAddFunction(function);
        } catch (Throwable e) {
            // ignore
        }

        verifyGrantRevoke(
                "drop global function my_udf_json_get (string, string);",
                "grant drop on ALL GLOBAL FUNCTIONS to test",
                "revoke drop on ALL GLOBAL FUNCTIONS from test",
                "Access denied; you need (at least one of) the DROP GLOBAL FUNCTION privilege(s) for this operation");

        verifyGrantRevoke(
                "drop global function my_udf_json_get (string, string);",
                "grant drop on GLOBAL FUNCTION my_udf_json_get(string,string) to test",
                "revoke drop on GLOBAL FUNCTION my_udf_json_get(string,string) from test",
                "Access denied; you need (at least one of) the DROP GLOBAL FUNCTION privilege(s) for this operation");
    }

    @Test
    public void testShowFunc() throws Exception {

        Database db1 = GlobalStateMgr.getCurrentState().getDb("db1");
        FunctionName fn = FunctionName.createFnName("db1.my_udf_json_get");
        Function function = new Function(fn, Arrays.asList(Type.STRING, Type.STRING), Type.STRING, false);
        try {
            db1.addFunction(function);
        } catch (Throwable e) {
            // ignore
        }
        String showSql = "show full functions in db1";
        String expectError = "Access denied for user 'test' to database 'db1'";
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(showSql, starRocksAssert.getCtx());
        ctxToTestUser();
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + showSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }
        ctxToRoot();
        grantOrRevoke("grant create_materialized_view on db1 to test");
        expectError = "Access denied; you need (at least one of) the TABLE/VIEW/MV privilege(s) for this operation";
        ctxToTestUser();
        try {
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (SemanticException e) {
            System.out.println(e.getMessage() + ", sql: " + showSql);
            Assert.assertTrue(e.getMessage().contains(expectError));
        }
        ctxToRoot();
        grantOrRevoke("grant select on db1.tbl1 to test");
        PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
        ctxToRoot();
        grantOrRevoke("revoke create_materialized_view on db1 from test");
        grantOrRevoke("revoke select on db1.tbl1 from test");
    }

    @Test
    public void testShowGlobalFunc() throws Exception {
        FunctionName fn = FunctionName.createFnName("my_udf_json_get");
        fn.setAsGlobalFunction();
        Function function = new Function(fn, Arrays.asList(Type.STRING, Type.STRING), Type.STRING, false);
        try {
            GlobalStateMgr.getCurrentState().getGlobalFunctionMgr().replayAddFunction(function);
        } catch (Throwable e) {
            // ignore
        }

        String showSql = "show full global functions";
        StatementBase statement = UtFrameUtils.parseStmtWithNewParser(showSql, starRocksAssert.getCtx());
        ctxToTestUser();
        PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
    }

    @Test
    public void testUseGlobalFunc() throws Exception {
        FunctionName fn = FunctionName.createFnName("my_udf_json_get");
        fn.setAsGlobalFunction();
        Function function = new Function(fn, Arrays.asList(Type.STRING, Type.STRING), Type.STRING, false);
        try {
            GlobalStateMgr.getCurrentState().getGlobalFunctionMgr().replayAddFunction(function);
        } catch (Throwable e) {
            // ignore
        }

        ctxToTestUser();
        String selectSQL = "select my_udf_json_get('hello', 'world')";
        try {
            StatementBase statement = UtFrameUtils.parseStmtWithNewParser(selectSQL, starRocksAssert.getCtx());
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
            Assert.fail();
        } catch (StarRocksPlannerException e) {
            System.out.println(e.getMessage() + ", sql: " + selectSQL);
            Assert.assertTrue(e.getMessage().contains("need the USAGE priv for GLOBAL FUNCTION"));
        }

        // grant usage on global function
        ctxToRoot();
        grantOrRevoke("grant usage on global function my_udf_json_get(string,string) to test");
        ctxToTestUser();

        try {
            Config.enable_udf = true;
            StatementBase statement = UtFrameUtils.parseStmtWithNewParser(selectSQL, starRocksAssert.getCtx());
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
        } finally {
            Config.enable_udf = false;
        }

        // grant on all global functions.
        ctxToRoot();
        grantOrRevoke("revoke usage on global function my_udf_json_get(string,string) from test");
        grantOrRevoke("grant usage on all global functions to test");
        ctxToTestUser();
        try {
            Config.enable_udf = true;
            StatementBase statement = UtFrameUtils.parseStmtWithNewParser(selectSQL, starRocksAssert.getCtx());
            PrivilegeCheckerV2.check(statement, starRocksAssert.getCtx());
        } finally {
            Config.enable_udf = false;
        }
    }
>>>>>>> d5c0f904f ([BugFix] Fix cancel decommission statement miss analyze (#16262))
}
