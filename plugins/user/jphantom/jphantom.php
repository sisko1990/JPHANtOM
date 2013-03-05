<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

class plgUserJPhantom extends JPlugin
{
    /**
     * Constructor
     *
     * @access protected
     *
     * @param  object $subject The object to observe
     * @param  array  $config  An array that holds the plugin configuration
     *
     * @since  1.5
     */
    public function __construct(& $subject, $config)
    {
        parent::__construct($subject, $config);
        $this->loadLanguage();

        // Load JPHANtOM library language
        $lang = JFactory::getLanguage();
        $lang->load('lib_jphantom', JPATH_SITE);
    }

    public function onUserBeforeSave($olduser, $isNew, $user)
    {
        // Define variables
        $minPasswordLength = (int)$this->params->get('password_length_min');
        $maxPasswordLength = (int)$this->params->get('password_length_max');

        $password = trim($user['password_clear']);
        $passwordLength = strlen($password);

        if(!empty($password) && !empty($user['password2']))
        {
            // Check if the user defined the password length wrong
            if($minPasswordLength <= $maxPasswordLength)
            {
                if($passwordLength <= $minPasswordLength)
                {
                    // Password is too short
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT_INFO', $minPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT'));
                    return false;
                }
                elseif($passwordLength >= $maxPasswordLength)
                {
                    // Password is too long
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_LONG_INFO', $maxPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_LONG'));
                    return false;
                }
            }
            else
            {
                if(JFactory::getUser()->authorise('core.manage', 'com_plugins'))
                {
                    JFactory::getApplication()->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_LENGTH_WRONG'), 'error');
                }

                // If the user defined the maxPasswordLength wrong, we only check the minPasswordLength
                if($passwordLength <= $minPasswordLength)
                {
                    // Password is too short
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT_INFO', $minPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT'));
                    return false;
                }
            }
        }

        return true;
    }


    public function onUserAfterSave($user, $isNew, $result, $errors)
    {
        if(!empty($user['password_clear']))
        {
            // Get the default hash algorithm
            $jPhantomAuthPlugin = & JPluginHelper::getPlugin('authentication', 'jphantom');
            $jPhantomAuthPluginParams = new JRegistry($jPhantomAuthPlugin->params);
            $defaultHashAlgorithm = $jPhantomAuthPluginParams->get('hashalgorithm', 'md5-hex');

            try
            {
                jimport('jphantom.jphantom');
                $jphantomlib = new JPhantomHashing();
                $jphantomlib->setDefaultHashAlgorithm($defaultHashAlgorithm);

                // Generate the new password hash
                $newPasswordHash = $jphantomlib->getHashForPassword($user['password_clear']);

                // Get a database object
                $db = JFactory::getDbo();
                $query = $db->getQuery(true);

                $query->update($db->quoteName('#__users'));
                $query->set($db->quoteName('password') . ' = ' . $db->quote($newPasswordHash));
                $query->where($db->quoteName('id') . ' = ' . $db->quote($user['id']));

                $db->setQuery($query)->query();
            }
            catch (Exception $exc)
            {
                throw new Exception($exc->getMessage());
            }
        }

        return true;
    }


}