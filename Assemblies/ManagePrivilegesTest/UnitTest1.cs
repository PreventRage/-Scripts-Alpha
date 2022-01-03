using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace ManagePrivilegesTest {
    [TestClass]
    public class UnitTest1 {
        [TestMethod]
        public void TestEnablePrivilege1() {
            Int64 hProcess = ManagePrivileges.HandleOfCurrentProcess;

            const string privilege = "SeTakeOwnershipPrivilege";
            bool success;
            bool isEnabled;
            success = ManagePrivileges.CheckPrivilege(hProcess, privilege, out isEnabled);
            Assert.IsTrue(success);
            Assert.IsFalse(isEnabled);
            success = ManagePrivileges.EnablePrivilege(hProcess, privilege);
            Assert.IsTrue(success);
            success = ManagePrivileges.CheckPrivilege(hProcess, privilege, out isEnabled);
            Assert.IsTrue(success);
            Assert.IsTrue(isEnabled);
        }
    }
}