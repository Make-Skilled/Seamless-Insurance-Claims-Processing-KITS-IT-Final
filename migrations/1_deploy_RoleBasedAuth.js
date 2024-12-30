const life=artifacts.require('RoleBasedAuth');

module.exports=function(deployer){
    deployer.deploy(life);
}