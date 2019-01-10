<?php

namespace Psecio\Versionscan;

class CheckFormatTest extends \PHPUnit_Framework_TestCase
{
    private $checks;

    protected function setUp()
    {
        $rawJson = file_get_contents(__DIR__.'/../../../src/Psecio/Versionscan/checks.json');
        $this->checks = json_decode($rawJson, true);
    }

    public function testEverythingIsUnderTheChecksKey()
    {
        $this->assertCount(1, $this->checks);
        $this->assertArrayHasKey('checks', $this->checks);
    }

    public function testStructureOfEachEntry()
    {
        foreach ($this->checks['checks'] as $check) {
            $this->assertArrayHasKey('cveid', $check, 'Entry found with no CVE ID');

            $id = $check['cveid'];

            $this->assertArrayHasKey('threat', $check, 'Missing "threat" for ' . $id);
            $this->assertArrayHasKey('summary', $check, 'Missing "summary" for ' . $id);
            $this->assertArrayHasKey('fixVersions', $check, 'Missing "fixVersions" for ' . $id);
            $this->assertArrayHasKey('base', $check['fixVersions'], 'Missing "fixVersions[base]" for ' . $id);

            // Make sure the versions are in order
            $versions = $check['fixVersions']['base'];
            $sortedVersions = $versions;
            natsort($sortedVersions);
            $this->assertSame($sortedVersions, $versions, 'Versions should be sorted in ascending order (' . $id . ')');
        }
    }

    public function testProperSortOrder()
    {
        $ids = $this->reduceArrayToCveList();
        $sortedIds = $ids;
        natsort($sortedIds);

        $this->assertSame($sortedIds, $ids, 'Checks should be sorted by their CVE ID');
    }

    public function testNoDuplicates()
    {
        $ids = $this->reduceArrayToCveList();
        $duplicates = array_unique(array_diff_assoc($ids, array_unique($ids)));
        natsort($duplicates);
        $this->assertEquals(0, count($duplicates), "Duplicate CVE IDs were found:\n - " . implode("\n - ", $duplicates));
    }

    private function reduceArrayToCveList()
    {
        $ids = array();
        foreach ($this->checks['checks'] as $check) {
            $ids[] = $check['cveid'];
        }

        return $ids;
    }
}