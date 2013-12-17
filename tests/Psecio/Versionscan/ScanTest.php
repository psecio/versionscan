<?php

namespace Psecio\Versionscan;

class ScanTest extends \PHPUnit_Framework_TestCase
{
    private $scan = null;

    public function setUp()
    {
        $this->scan = new Scan();
    }

    /**
     * Check the getter/setter for the PHP version
     *
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::getVersion
     */
    public function testVersionGetterSetter()
    {
        $phpVersion = '5.2.12';
        $this->scan->setVersion($phpVersion);

        $this->assertEquals(
            $this->scan->getVersion(),
            $phpVersion
        );
    }

    /**
     * Verify that the checks are corrected loaded
     *
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     */
    public function testSetChecksArray()
    {
        $checks = array(
            array(
                'cveid' => 'CVE-1234',
                'summary' => 'This is a test',
                'fixVersions' => array(
                    '5.4.0'
                )
            )
        );
        $this->scan->setChecks($checks);

        $checks = $this->scan->getChecks();
        $this->assertTrue(is_object($checks[0]));

        $cveId = $checks[0]->getCveId();
        $this->assertTrue($cveId !== null);
        $this->assertEquals($cveId, 'CVE-1234');
    }

    /**
     * Check the setting of the version when the scan is initiated
     *
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::execute
     */
    public function testSetVersionOnInit()
    {
        $phpVersion = '5.4.1';
        $scan = new Scan();
        $scan->execute($phpVersion, array());

        $this->assertEquals(
            $scan->getVersion(),
            $phpVersion
        );
    }

    /**
     * Check that the value for PHP_VERSION is returned by default
     *
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::getVersion
     */
    public function testSetDefaultVersionOnInit()
    {
        $scan = new Scan();
        $scan->execute(null, array());

        $this->assertEquals(
            $scan->getVersion(),
            PHP_VERSION
        );
    }

    /**
     * Test that a run with valid criteria runs correctly
     *
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::runChecks
     */
    public function testRunTestsValid()
    {
        $checks = array(
            array(
                'cveid' => 'CVE-1234',
                'summary' => 'This is a test',
                'fixVersions' => array('5.1.1')
            )
        );
        $phpVersion = '5.4.1';

        $scan = new Scan();
        $scan->execute($phpVersion, $checks);

        $checks = $scan->getChecks();
        $this->assertFalse($checks[0]->getResult());
    }
}