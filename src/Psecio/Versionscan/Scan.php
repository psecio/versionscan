<?php

namespace Psecio\Versionscan;

class Scan
{
    private $checks = array();

    public function execute()
    {
        // pull in the Scan checks
        $checks = json_decode(file_get_contents(__DIR__.'/checks.json'));
        print_r($checks);
        foreach ($checks->checks as $check) {
            $this->checks[] = new \Psecio\Versionscan\Check($check);
        }
        print_r($this->checks);
    }
}