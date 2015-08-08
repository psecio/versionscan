<?php
namespace Psecio\Versionscan\Command\ScanCommand\Output;

use Psecio\Versionscan\Command\Output;
use Symfony\Component\Console\Command\Command;

class Json extends Output
{
    public function render($results, Command $command)
    {
        $output = $this->getOutput();

        $output->writeLn(json_encode(array('results' => $results)));
    }
}
