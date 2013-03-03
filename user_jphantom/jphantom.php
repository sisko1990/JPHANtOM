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

    public function onUserBeforeSave($olduser, $isNew, $user)
    {
        // Load JPHANtOM library language
        $lang = JFactory::getLanguage();
        $lang->load('lib_jphantom', JPATH_SITE);

        jimport('jphantom.jphantom');
        $jphantomlib = new JPhantomLib();
        //$jphantomlib->setDefaultHashAlgorithm('drupal');

        /*
          echo '<pre>';
          var_dump($olduser);
          echo '</pre>';

          echo '<pre>';
          var_dump($isNew);
          echo '</pre>';

          echo '<pre>';
          var_dump($user);
          echo '</pre>';
         */

        //$user['password'] = $jphantomlib->getHashForPassword($user['password_clear']);
        throw new Exception('Test');

        return false;
    }



    public function onUserAfterSave($user, $isNew, $result, $errors)
    {
        jimport('jphantom.jphantom');
        $jphantomlib = new JPhantomLib();
        //$jphantomlib->setDefaultHashAlgorithm('drupal');
        // Generate the new password hash
        $newPasswordHash = $jphantomlib->getHashForPassword($user['password_clear']);

        // Get a database object
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);

        $query->update($db->quoteName('#__users'));
        $query->set($db->quoteName('password') . ' = ' . $db->quote($newPasswordHash));
        $query->where($db->quoteName('id') . ' = ' . $db->quote($user['id']));

        $db->setQuery((string) $query)->query();

        return true;
    }



}