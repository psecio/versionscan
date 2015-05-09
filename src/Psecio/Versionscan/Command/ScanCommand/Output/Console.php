<?php

namespace Psecio\Versionscan\Command\ScanCommand\Output;

use Psecio\Versionscan\Command\Output;
use Symfony\Component\Console\Command\Command;

class Console extends Output
{
    public function render($results, Command $command)
    {
        $phpVersion = $this->getOption('phpVersion');
        $checksCount = $this->getOption('checksCount');
        $failCount = $this->getOption('failCount');
        $output = $this->getOutput();

        $output->writeLn('Executing against version: ' . $phpVersion);

        $table = $command->getHelper('table');
        $table->setHeaders(array('Status', 'CVE ID', 'Risk', 'Summary'));

        $rows = array();
        $column = 100;

        for ($i = 0, $length = count($results); $i < $length; $i++) {
            $results[$i]['status'] = 'fail' ? '<fg=red>FAIL</fg=red>' : '<fg=green>PASS</fg=green>';
            $results[$i]['summary'] = !$output->isVerbose() && strlen($results[$i]['summary']) > $column
                ? substr($results[$i]['summary'], 0, $column - 3) . '...'
                : $results[$i]['summary'];
        }

        $table->setRows($results);
        $table->render($output);

        $output->writeLn(sprintf(
            "\nScan complete\n%s\nTotal checks: %s\n<fg=red>Failures: %s</fg=red>\n",
            str_repeat('-', 20),
            $checksCount,
            $failCount
        ));
    }
}
