const life=artifacts.require('UserManagement');

module.exports=function(deployer){
    deployer.deploy(life);
}