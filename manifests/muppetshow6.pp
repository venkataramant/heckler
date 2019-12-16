class muppetshow {
  file { "${facts['cwd']}/nodes":
    ensure => directory,
  }
  package { 'nginx':
    ensure => installed,
  }
  $the_muppet_show = @(EOF)
    It's the Muppet Show

    It's time to play the music
    It's time to light the lights
    It's time to meet the Muppets on the Muppet Show tonight
    It's time to put on make up
    It's time to dress up right
    It's time to raise the curtain on the Muppet Show tonight

    Why do we always come here
    I guess we'll never know
    It's like a kind of torture
    To have to watch the show

    But now let's get things started
    Why don't you get things started
    It's time to get things started
    On the most sensational, inspirational, celebrational, muppetational
    This is what we call the Muppet Show
    | EOF

  file { "${facts['cwd']}/nodes/the_muppet_show":
    ensure => present,
    content => $the_muppet_show,
  }
  muppetshow::episode { "One":
    base => "${facts['cwd']}/nodes",
  }
  concat { "${facts['cwd']}/nodes/cast":
    ensure => present,
  }
  concat::fragment { 'MissPiggy':
    target  => "${facts['cwd']}/nodes/cast",
    content => "Miss Piggy\n",
    order   => '01'
  }
  concat::fragment { 'RowlfTheDog':
    target  => "${facts['cwd']}/nodes/cast",
    content => "Rowlf the Dog\n",
    order   => '02'
  }
}
