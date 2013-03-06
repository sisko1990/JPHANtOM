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
        $minPasswordLength = (int)$this->params->get('password_length_min', '6');
        $maxPasswordLength = (int)$this->params->get('password_length_max', '50');
        $digitsCheck = (int)$this->params->get('password_complexity_digits', '0');
        $upperAndLowerCheck = (int)$this->params->get('password_complexity_upper_and_lower', '0');
        $usernameForbiddenCheck = (int)$this->params->get('password_forbidden_text_username', '0');
        $emailForbiddenCheck = (int)$this->params->get('password_forbidden_text_email', '0');

        $password = trim($user['password_clear']);
        $passwordLength = strlen($password);

        if (!empty($password) && !empty($user['password2']))
        {
            /* Password length check */

            // Check if the user defined the password length wrong
            if ($minPasswordLength <= $maxPasswordLength)
            {
                if ($passwordLength <= $minPasswordLength)
                {
                    // Password is too short
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT_INFO', $minPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT'));
                }
                elseif ($passwordLength >= $maxPasswordLength)
                {
                    // Password is too long
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_LONG_INFO', $maxPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_LONG'));
                }
            }
            else
            {
                if (JFactory::getUser()->authorise('core.manage', 'com_plugins'))
                {
                    JFactory::getApplication()->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_LENGTH_WRONG'), 'error');
                }

                // If the user defined the maxPasswordLength wrong, we only check the minPasswordLength
                if ($passwordLength <= $minPasswordLength)
                {
                    // Password is too short
                    JFactory::getApplication()
                        ->enqueueMessage(JText::sprintf('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT_INFO', $minPasswordLength), 'info');
                    throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_PASSWORD_TO_SHORT'));
                }
            }

            /* Password complexity check */
            jimport('jphantom.password.validation');
            $passwordValidation = new JPhantomPasswordValidation($password);

            if ($digitsCheck === 1 && $passwordValidation->hasDigits() === false)
            {
                JFactory::getApplication()
                    ->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_NO_DIGITS_INFO'), 'info');
                throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_NO_DIGITS'));
            }
            elseif ($upperAndLowerCheck === 1 && $passwordValidation->hasUpperAndLowerCaseLetters() === false)
            {
                JFactory::getApplication()
                    ->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_NO_UPPER_AND_LOWER_INFO'), 'info');
                throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_NO_UPPER_AND_LOWER'));
            }
            elseif ($usernameForbiddenCheck === 1 && $passwordValidation->hasForbiddenText(array($user['username'], $user['name'])) === true)
            {
                JFactory::getApplication()
                    ->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_USERNAME_IN_PASSWORD_INFO'), 'info');
                throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_USERNAME_IN_PASSWORD'));
            }
            elseif ($emailForbiddenCheck === 1 && $passwordValidation->hasForbiddenText((string)$user['email']) === true)
            {
                JFactory::getApplication()
                    ->enqueueMessage(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_EMAIL_IN_PASSWORD_INFO'), 'info');
                throw new Exception(JText::_('PLG_USER_JPHANTOM_ERROR_COMPLEXITY_EMAIL_IN_PASSWORD'));
            }
        }

        return true;
    }


    public function onUserAfterSave($user, $isNew, $result, $errors)
    {
        if (!empty($user['password_clear']))
        {
            // Get the default hash algorithm
            $jPhantomAuthPlugin = & JPluginHelper::getPlugin('authentication', 'jphantom');
            $jPhantomAuthPluginParams = new JRegistry($jPhantomAuthPlugin->params);
            $defaultHashAlgorithm = $jPhantomAuthPluginParams->get('hashalgorithm', 'md5-hex');

            try
            {
                jimport('jphantom.password.hashing');
                $jphantomlib = new JPhantomPasswordHashing();
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