<?php
namespace Psecio\Versionscan\Command\ScanCommand\Output;

use Psecio\Versionscan\Command\Output;
use Symfony\Component\Console\Command\Command;

class Xml extends Output
{
    public function render($results, Command $command)
    {
        $output = $this->getOutput();

        $resultValues = $results;

        $dom = new \DomDocument('1.0', 'UTF-8');

        $results = $dom->createElement('results');

        foreach ($resultValues as $result) {
            $resultXml = $dom->createElement('result');

            foreach ($result as $name => $value) {
                $property = $dom->createElement($name, $value);
                $resultXml->appendChild($property);
            }

            $results->appendChild($resultXml);
        }

        $dom->appendChild($results);

        $output->writeLn($dom->saveXML());
    }
}
