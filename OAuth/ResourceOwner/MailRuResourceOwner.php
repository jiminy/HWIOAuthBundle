<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;

/**
 * MailRuResourceOwner
 *
 * @author Gaponov Igor <jiminy96@gmail.com>
 */
class MailRuResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritDoc}
     */
    protected $options = array(
        'authorization_url'   => 'https://connect.mail.ru/oauth/authorize',
        'access_token_url'    => 'https://connect.mail.ru/oauth/token',
        'infos_url'           => 'http://www.appsmail.ru/platform/api',

        'method'              => 'users.getInfo',
        'secure'              => '1',
    );

    /**
     * {@inheritDoc}
     */
    protected $paths = array(
        'identifier' => 'uid',
        'nickname'   => 'nick',
        'email'      => 'email',
    );

    /**
     * {@inheritDoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        $params = array(
            'session_key' => $accessToken['access_token'],
            'app_id'    => $this->getOption('client_id'),
            'method' => $this->getOption('method'),
            'secure' => $this->getOption('secure'),
        );

        ksort($params);

        $sig = '';
        foreach ($params as $key => $value) {
            $sig .= "$key=$value";
        }
        $params['sig'] = md5($sig . $this->getOption('client_secret'));

        $url = $this->normalizeUrl($this->getOption('infos_url'), $params);

        $content = $this->doGetUserInformationRequest($url)->getContent();

        $response = $this->getUserResponse();
        $response->setResponse($content);
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }
}