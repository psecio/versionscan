<?php

namespace Psecio\Versionscan;

class CheckTest extends \PHPUnit_Framework_TestCase
{
    private $check = null;

    public function setUp()
    {
        $this->check = new Check();
    }

    /**
     * Check the getters/setters for the check
     */
    public function testCheckGetterSetter()
    {
        $data = array(
            'threat' => '6.4',
            'cveid' => 'CVE-2014-5120',
            'summary' => 'gd_ctx.c in the GD component in PHP 5.4.x before 5.4.32 and 5.5.x before 5.5.16 does not ensure that pathnames lack %00 sequences, which might allow remote attackers to overwrite arbitrary files via crafted input to an application that calls the (1) imagegd, (2) imagegd2, (3) imagegif, (4) imagejpeg, (5) imagepng, (6) imagewbmp, or (7) imagewebp function. \nPublish Date : 2014-08-22 Last Update Date : 2014-08-27',
            'fixVersions' => (object)array(
                'base' => array('5.4.32', '5.5.16')
            )
        );
        $this->check->setData($data);

        $this->assertSame($data['threat'], $this->check->getThreat());
        $this->assertSame($data['cveid'], $this->check->getCveId());
        $this->assertSame($data['summary'], $this->check->getSummary());
        $this->assertSame($data['fixVersions']->base, $this->check->getVersions());
    }

    /**
     * Check the pass/fail functions
     */
    public function testCheckPassFail()
    {
        $this->check->pass();
        $this->assertTrue($this->check->getResult());
        $this->check->fail();
        $this->assertFalse($this->check->getResult());
    }

    /**
     * Check the isVulnerable check
     */
    public function testIsVulnerableWorksCorrectly()
    {
        $this->check->setData(array(
            'fixVersions' => (object)array(
                'base' => array('5.4.32', '5.5.16')
            )
        ));

        $this->assertTrue($this->check->isVulnerable('5.4.31'));
        // Even though 5.4.33 is < 5.5.16, it still passes because there is a branch match
        $this->assertFalse($this->check->isVulnerable('5.4.33'));
        $this->assertFalse($this->check->isVulnerable('5.5.16'));
        // Even though 5.3.0 is < 5.5.16, it still passes this vulnerability doesn't affect this branch
        $this->assertFalse($this->check->isVulnerable('5.3.0'));
        $this->assertFalse($this->check->isVulnerable('5.6.0'));
    }

    /**
     * Check the isVulnerable check fails if an invalid version is supplied
     */
    public function testIsVulnerableFail()
    {
        $this->setExpectedException('InvalidArgumentException', 'Could not determine major version');
        $this->check->isVulnerable('invalid-version');
    }
}