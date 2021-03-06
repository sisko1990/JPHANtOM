﻿<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

/**
 * JPHANtOM authentication plugin
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
     *
     * @param array  Array holding the user credentials
     * @param array  Array of extra options
     * @param object Authentication response object
     *
     * @return boolean
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        jimport('joomla.user.helper');

        $response->type = 'JPHANtOM';
        // Joomla does not like blank passwords
        if (empty($credentials['password']))
        {
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

            return false;
        }

        // Initialise variables.
        $conditions            = '';
        $paramHashAlgorithm    = $this->params->get('hashalgorithm');
        $paramLoginAlternative = $this->params->get('loginalternative');

        // Get a database object
        $db    = JFactory::getDbo();
        $query = $db->getQuery(true);

        $query->select($db->quoteName(array('id', 'password')));
        $query->from($db->quoteName('#__users'));

        if ($paramLoginAlternative === 'username_and_email')
        {
            $query->where(array($db->quoteName('username') . ' = ' . $db->quote($credentials['username']),
                $db->quoteName('email') . ' = ' . $db->quote($credentials['username'])), 'OR');
        }
        elseif ($paramLoginAlternative === 'email_only')
        {
            $query->where($db->quoteName('email') . ' = ' . $db->quote($credentials['username']));
        }
        else
        {
            $query->where($db->quoteName('username') . ' = ' . $db->quote($credentials['username']));
        }

        $db->setQuery($query);
        $result = $db->loadObject();

        if ($result)
        {
            jimport('jphantom.password.hashing');
            $jphantomlib = new JPhantomPasswordHashing();
            $jphantomlib->setDefaultHashAlgorithm($paramHashAlgorithm);

            try
            {
                if ($jphantomlib->checkPasswordWithStoredHash($result->password, $credentials['password'], (int)$result->id) === true)
                {
                    $user               = JUser::getInstance($result->id);
                    $response->username = $user->username;
                    $response->email    = $user->email;
                    $response->fullname = $user->name;

                    if (JFactory::getApplication()->isAdmin())
                    {
                        $response->language = $user->getParam('admin_language');
                    }
                    else
                    {
                        $response->language = $user->getParam('language');
                    }
                    $response->status        = JAuthentication::STATUS_SUCCESS;
                    $response->error_message = '';
                }
            }
            catch (Exception $exc)
            {
                $response->status        = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_($exc->getMessage());
            }
        }
        else
        {
            $response->status        = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
        }
    }


}