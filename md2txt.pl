use strict;
use warnings;
use Text::Wrap;
use Getopt::Long;

my $input_file;
my $output_file;
my $numeric_refs;
my $left_margin = 0;
my $page_width = $Text::Wrap::columns;
my $indent_tab;
my $example_indent = 4;

use constant {
    ENV_PARA => 0,
    ENV_EXAMPLE => 1,
    ENV_ENUM => 2,
    ENV_ITEMIZE => 3,
    ENV_SECTION => 4,
    ENV_REFS => 5
};

GetOptions('numeric-refs|N' => \$numeric_refs,
	   'left-margin|l=n' => \$left_margin,
	   'page-width|w=n' => \$page_width,
           'output|o=s' => \$output_file)
    or exit(1);

$indent_tab = ' ' x $left_margin;

$input_file = shift @ARGV or die "required parameter missing\n";

open(STDIN, '<', $input_file) or die "can't open $input_file: $!\n";

if ($output_file) {
    open(STDOUT, '>', $output_file) or die "can't open output file $output_file: $!\n";
}

convert();
exit 0;

#
# Inline markup
#
sub expand_inline {
    $_ = join(' ', @_);
    s{\*([^*]+)\*}{$1}g;
    s{__(.+?)__}{$1}g; 
    s{\`([^`]+)\`}{$1}g;
    s{\[(.*?)\]\((https?://.*?)\)}{external_ref($1, $2)}gex;
    
    return $_;
}

my %refidx;
my $refs;
my @epilogue;

sub external_ref {
    my ($name, $url) = @_;
    my $refname;

    unless (defined($refs)) {
	push @epilogue, { env => ENV_SECTION, level => 1, content => ["References"] };
	$refs = { env => ENV_REFS, content => [] };	   
	push @epilogue, $refs;
    }
    
    if (exists($refidx{$url})) {
	$refname = $refs->{content}[$refidx{$url}]->{name}
    } else {
	$refname = @{$refs->{content}}; # FIXME: take into account $numeric_refs
	$refidx{$url} = @{$refs->{content}};
	push @{$refs->{content}}, { name => $refname, url => $url }
    }
	
    return "$name\[$refname\]";
}

sub format_refs {
    my $para = shift;
    foreach my $elem (@{$para->{content}}) {
	print "$indent_tab\[$elem->{name}\] $elem->{url}\n";
    }
    print "\n";
}
#
# Converter
#
my %envfun;

BEGIN {
    %envfun = (
	ENV_SECTION() => {
	    collect => \&collect_section,
	    format => \&format_section
	},
	ENV_PARA() => {
	    collect => \&collect_para,
	    format => \&format_para,
	},
	ENV_ENUM() => {
	    collect => \&collect_enum,
	    format => \&format_enum
	},
	ENV_ITEMIZE() => {
	    collect => \&collect_itemize,
	    format => \&format_itemize
	},
	ENV_EXAMPLE() => {
	    collect => \&collect_example,
	    format => \&format_example
	},
	ENV_REFS() => {
	    collect => sub { die "Should not happen: collect_refs called!" },
	    format => \&format_refs
	}
    );
}

use Data::Dumper;

sub convert {
    local $Text::Wrap::columns = $page_width - $left_margin;
    local $Text::Wrap::huge = 'overflow';
    my $para;
    
    while ($para = collect($para)) {
	&{$envfun{$para->{env}}{format}}($para);
    }
}


# Collect a single paragraph of text.
sub collect {
    my $prev = shift;
    my $res = { env => ENV_PARA, content => [] };
    
    if (defined($prev) && exists($prev->{pushback})) {
	$_ = $prev->{pushback};
    } else {
	while (<>) {
	    chomp;
	    last unless /^$/;
	}
	unless (defined($_)) {
	    return shift @epilogue;
	}
    }
    
    if (m{^#+\s+\S}) {
	$res->{env} = ENV_SECTION;
    } elsif (m{^[0-9]+[.)]}) {
	$res->{env} = ENV_ENUM;
    } elsif (m{^\*\s+}) {
	$res->{env} = ENV_ITEMIZE;
    } elsif (m{^\s*```}) {
	$res->{env} = ENV_EXAMPLE;
    }
    return &{$envfun{$res->{env}}{collect}}($res, $_);
}

sub collect_section {
    my ($res, $init) = @_;
    $init =~ m{^(#+)\s+(.*)};
    $res->{content}[0] = $2;
    $res->{level} = length($1);
    return $res;
}

sub collect_para {
    my ($res, $init) = @_;
    $init =~ s/^\s+//;
    push @{$res->{content}}, $init;
    while (<>) {
	chomp;
	return $res if $_ eq '';
	s/^\s+//;
	push @{$res->{content}}, $_;
    }
    return $res if @{$res->{content}};
}

sub collect_example {
    my ($res, $init) = @_;
    while (<>) {
	chomp;
	return $res if m{^\s*```};
	push @{$res->{content}}, $_;
    }
}

sub collect_itemized_env {
    my ($rx, $res, $text) = @_;
    my $lookahead;
    $text =~ s{$rx}{};
    while (<>) {
	chomp;
	if ($lookahead) {
	    if (m/^$/) {
		$lookahead .= "\n";
	    } elsif (s{$rx}{}) {
	        push @{$res->{content}}, $text . $lookahead;
	        $text = $_;
		$lookahead = undef
	    } else {
	        push @{$res->{content}}, $text;
		#FIXME: pushback
		$res->{pushback} = $_;
		return $res;
	    }
	} elsif (s{$rx}{}) {
	    push @{$res->{content}}, $text;
	    $text = $_;
	} elsif (m/^$/) {
	    $lookahead = "\n";
	} else {
	    $text .= ' ' . $_
	}
    }
    push @{$res->{content}}, $text unless $text eq '';
    return $res if @{$res->{content}};
}

sub collect_enum {
    my ($res, $text) = @_;
    collect_itemized_env(qr{^[0-9]+[.)]\s*}, $res, $text)
}

sub collect_itemize {
    my ($res, $text) = @_;
    collect_itemized_env(qr{^\*\s+}, $res, $text)
}

sub format_section {
    my $res = shift;
    my $h = expand_inline($res->{content}[0]);
    my $len = length($h);
    if ($len < $Text::Wrap::columns) {
	print ' ' x (($Text::Wrap::columns - $len) / 2);
    }
    print "$h\n";
    if ($len < $Text::Wrap::columns) {
	print ' ' x (($Text::Wrap::columns - $len) / 2);
    }
    my $delim;
    if ($res->{level} == 1) {
	$delim = '=';
    } elsif ($res->{level} == 2) {
	$delim = '-';
    } else {
	$delim = '.';
    }
    print $delim x $len;
    print "\n\n";
}
       
sub format_para {
    my $para = shift;
    my $text = fill($indent_tab, $indent_tab, expand_inline(@{$para->{content}}));
    print $text."\n\n";
}

sub format_example {
    my $para = shift;
    my $indent = $indent_tab . (' ' x $example_indent);
    print $indent, join("\n$indent", @{$para->{content}}), "\n\n";
}

sub format_enum {
    my $para = shift;
#    print Dumper([$para]);
    my $n = @{$para->{content}};
    my $indent_len = length("$n. ");
    my $indent_pfx = $indent_tab . (' ' x $indent_len);
    my $i = 1;
    foreach my $elem (@{$para->{content}}) {
	print "$indent_tab$i. ";
	$i++;
	print fill(' ' x (length("$n. ") - $indent_len), $indent_pfx,
		   expand_inline($elem));
	if ($elem =~ m{(\n+)$}sm) {
	    print $1
	} else {
	    print "\n";
	}
    }
    print "\n";
}
	
sub format_itemize {
    my $para = shift;
    foreach my $elem (@{$para->{content}}) {
	print fill("$indent_tab* ", "$indent_tab  ", expand_inline($elem));
	if ($elem =~ m{(\n+)$}sm) {
	    print $1
	} else {
	    print "\n";
	}
    }
    print "\n";
}




