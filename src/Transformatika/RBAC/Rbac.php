<?php
namespace Transformatika\RBAC;


use Db\UserGroupQuery;
class Rbac
{
	const ERROR_ACCESS = 'Youre not authorized';

	protected $whiteList = array();

	protected $sessionKey = 'userId';

	public function __construct()
	{

	}

	public function getWhiteList()
	{
		return $this->whiteList;
	}

	public function setWhiteList($whiteList)
	{
		$this->whiteList = $whiteList;
		return $this;
	}

	public function check($match='')
	{
		if(in_array($match, $this->whiteList)){
			return true;
		}else{
			if (!isset($_SESSION[$this->sessionKey])) {
				header('HTTP/1.0 403 Forbidden');
				echo 'Please Login';
				exit();
			} else {
				if(!isset($_SESSION['rbacPermission'])){
					$this->getRoles();
				}
				$listCurrentRoles = explode('|',$_SESSION['rbacPermission']);
				if (!in_array($match, $listCurrentRoles)){
					header('HTTP/1.0 403 Forbidden');
					echo 'Access Denied';
					exit();
				} else {
					return true;
				}
			}
		}
	}

	protected function checkRole($match='')
	{
		$listCurrentRoles = explode('|',$_SESSION['rbacPermission']);
		if (in_array($match, $listCurrentRoles)) {
			return true;
		} else {
			return false;
		}
	}

	public function getRoles()
	{
		if (!isset($_SESSION[$this->sessionKey])) {
			$_SESSION['rbacPermission'] = '';
		} else {
			$userGroup = UserGroupQuery::create()->findByUserId($_SESSION[$this->sessionKey]);
			$userRoles = array();
			foreach($userGroup as $key=>$obj){
				$permission = $obj->getGroupPermission();
				$listPermission = $permission->getPermission();
				foreach($listPermission as $k=>$v){
					$userRoles[] = $v->getMatch();
				}
			}
			$_SESSION['rbacPermission'] = implode('|',$userRoles);
		}
	}

	public function addRoles($match, $name)
	{

	}


}
