<?php

/**
 * @copyright Copyright (C) 2005 - 2012 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

/**
 * Joomla secure password hashes authentication plugin
 *
 * @package    Joomla.Plugin
 * @subpackage Authentication.jphantom
 */
class plgAuthenticationJPhantom extends JPlugin
{

    /**
     * This method should handle any authentication and report back to the subject.
     *
     * @access public
     * @param	 array	 Array holding the user credentials
     * @param	 array	 Array of extra options
     * @param	 object	 Authentication response object
     * @return boolean
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        jimport('joomla.user.helper');

        $response->type = 'JPHANtOM';
        // Joomla does not like blank passwords
        if (empty($credentials['password']))
        {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
            return false;
        }

        jimport('jphantom.jphantom');
        $jphantomlib = new JPhantomLib();

        // Initialise variables.
        $conditions = '';
    }
}