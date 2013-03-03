<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
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

        // Initialise variables.
        $conditions = '';

        // Get a database object
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);

        $query->select('id, password');
        $query->from('#__users');
        $query->where('username = ' . $db->Quote($credentials['username']));
        $db->setQuery($query);
        $result = $db->loadObject();

        if ($result)
        {
            jimport('jphantom.jphantom');
            $jphantomlib = new JPhantomLib();
            //$jphantomlib->setDefaultHashAlgorithm('drupal');
            // @TODO: Fix problem if user password is shorter than 6 characters.
            // Maybe force user to change the password immediately?!
            try
            {
                if ($jphantomlib->checkPasswordWithStoredHash($result->password, $credentials['password'], (int) $result->id) === true)
                {
                    $user = JUser::getInstance($result->id);
                    $response->username = $user->username;
                    $response->email = $user->email;
                    $response->fullname = $user->name;

                    if (JFactory::getApplication()->isAdmin())
                    {
                        $response->language = $user->getParam('admin_language');
                    }
                    else
                    {
                        $response->language = $user->getParam('language');
                    }
                    $response->status = JAuthentication::STATUS_SUCCESS;
                    $response->error_message = '';
                }
            }
            catch (InvalidPassException $ipexc)
            {
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
            }
            catch (NoUserException $nuexc)
            {
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
            }
        }
        else
        {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
        }
    }



}