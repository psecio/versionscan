<?php

namespace Psecio\Versionscan;

class Check
{
    private $cveid = null;
    private $summary = '';
    private $fixVersions = array();

    public function __construct($checkData)
    {
        $this->setData($checkData);
    }

    public function setData($checkData)
    {
        $checkData = (is_object($checkData))
            ? get_object_vars($checkData) : $checkData;

        foreach ($checkData as $key => $data) {
            $this->$key = $data;
        }
    }

    public function getVersions()
    {
        return $this->fixVersions;
    }
}