<?php

namespace Transformatika\RBAC;

use Propel\Table\UserGroupQuery;
use Propel\Table\GroupPermissionQuery;

class Rbac
{
    const ERROR_ACCESS = 'Youre not authorized';

    protected $whiteList = array();

    protected $sessionKey = 'userId';
    
    protected $loginUrl = '';
    
    protected $deniedUrl = '';

    public function __construct()
    {
    }
    
    public function getLoginUrl()
    {
    	return $this->loginUrl;
    }
    
    /**
     * Set Login URL
     * 
     * @param string $url
     */
    public function setLoginUrl($url)
    {
    	$this->loginUrl = $url;
    	return $this;
    }
	
    /**
     * Get WhiteList
     * 
     * @return aray
     */
    public function getWhiteList()
    {
        return $this->whiteList;
    }
	
    /**
     * Set WhiteList
     * 
     * @param unknown $whiteList
     * @return \Transformatika\RBAC\Rbac
     */
    public function setWhiteList($whiteList)
    {
        $this->whiteList = $whiteList;

        return $this;
    }
	
    /**
     * Check Permission
     * 
     * @param string $match
     * @return boolean
     */
    public function check($match = '')
    {
        if (isset($_SESSION['userSu']) && $_SESSION['userSu'] === 'y') {
            return true;
        }
        if (in_array($match, $this->whiteList)) {
            return true;
        } else {
            if (!isset($_SESSION[$this->sessionKey])) {
                header('HTTP/1.0 403 Forbidden');
                if (empty($this->loginUrl)) {
                	echo 'Please Login';
                } else {
                	header('location:'.$this->loginUrl);	
                }
                exit();
            } else {
                if (!isset($_SESSION['rbacPermission'])) {
                    $this->getRoles();
                }
                $listCurrentRoles = explode('|', $_SESSION['rbacPermission']);
                if (!in_array($match, $listCurrentRoles)) {
                	if (empty($this->deniedUrl)) {
                		header('HTTP/1.0 403 Forbidden');
                		echo 'Access Denied';
                	} else {
                		header('location:'.$this->deniedUrl);	
                	}
                    exit();
                } else {
                    return true;
                }
            }
        }
    }

    protected function checkRole($match = '')
    {
        if ($_SESSION['userSu'] === 'y') {
            return true;
        } else {
            $listCurrentRoles = explode('|', $_SESSION['rbacPermission']);
            if (in_array($match, $listCurrentRoles)) {
                return true;
            } else {
                return false;
            }
        }
    }
	
    /**
     * Get User Permission
     */
    public function getRoles()
    {
        if (!isset($_SESSION[$this->sessionKey])) {
            $_SESSION['rbacPermission'] = '';
        } else {
            $userGroup = UserGroupQuery::create()->findByUserId($_SESSION[$this->sessionKey]);
            $userPermission = array();
            foreach ($userGroup as $k => $group) {
                $groupPermission = GroupPermissionQuery::create()->findByGroupId($group->getGroupId());
                foreach ($groupPermission as $key => $permission) {
                    $match = $permission->getPermission()->getMatch();
                    if (!in_array($match, $userPermission)) {
                        $userPermission[] = $match;
                    }
                }
            }
            $_SESSION['rbacPermission'] = implode('|', $userPermission);
        }
    }

    public function addRoles($match, $name)
    {
    }
}
