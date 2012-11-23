require 'rspec'
require 'krypt'

describe Krypt::ASN1 do 
  let(:mod) { Krypt::ASN1 }

  it "defines constants for UNIVERSAL tags" do
    mod::END_OF_CONTENTS.should == 0
    mod::BOOLEAN.should == 1
    mod::INTEGER.should == 2
    mod::BIT_STRING.should == 3
    mod::OCTET_STRING.should == 4
    mod::NULL.should == 5
    mod::OBJECT_ID.should == 6

    mod::ENUMERATED.should == 10

    mod::UTF8_STRING.should == 12

    mod::SEQUENCE.should == 16
    mod::SET.should == 17
    mod::NUMERIC_STRING.should == 18
    mod::PRINTABLE_STRING.should == 19
    mod::T61_STRING.should == 20
    mod::VIDEOTEX_STRING.should == 21
    mod::IA5_STRING.should == 22
    mod::UTC_TIME.should == 23
    mod::GENERALIZED_TIME.should == 24
    mod::GRAPHIC_STRING.should == 25
    mod::ISO64_STRING.should == 26
    mod::GENERAL_STRING.should == 27
    mod::UNIVERSAL_STRING.should == 28

    mod::BMP_STRING.should == 30
  end

  describe '::UNIVERSAL_TAG_NAME' do

    let(:ary) { Krypt::ASN1::UNIVERSAL_TAG_NAME }

    it "UNIVERSAL_TAG_NAME defines name of the constants
        corresponding to a given tag. If a class is not 
        supported, the value at the corresponding index is nil" do
      ary[mod::END_OF_CONTENTS].should == "END_OF_CONTENTS"
      ary[mod::BOOLEAN].should == "BOOLEAN"
      ary[mod::INTEGER].should == "INTEGER"
      ary[mod::BIT_STRING].should == "BIT_STRING"
      ary[mod::OCTET_STRING].should == "OCTET_STRING"
      ary[mod::NULL].should == "NULL"
      ary[mod::OBJECT_ID].should == "OBJECT_ID"
      ary[mod::ENUMERATED].should == "ENUMERATED"
      ary[mod::UTF8_STRING].should == "UTF8_STRING"
      ary[mod::SEQUENCE].should == "SEQUENCE"
      ary[mod::SET].should == "SET"
      ary[mod::NUMERIC_STRING].should == "NUMERIC_STRING"
      ary[mod::PRINTABLE_STRING].should == "PRINTABLE_STRING"
      ary[mod::T61_STRING].should == "T61_STRING"
      ary[mod::VIDEOTEX_STRING].should == "VIDEOTEX_STRING"
      ary[mod::IA5_STRING].should == "IA5_STRING"
      ary[mod::UTC_TIME].should == "UTC_TIME"
      ary[mod::GENERALIZED_TIME].should == "GENERALIZED_TIME"
      ary[mod::GRAPHIC_STRING].should == "GRAPHIC_STRING"
      ary[mod::ISO64_STRING].should == "ISO64_STRING"
      ary[mod::GENERAL_STRING].should == "GENERAL_STRING"
      ary[mod::UNIVERSAL_STRING].should == "UNIVERSAL_STRING"
      ary[mod::BMP_STRING].should == "BMP_STRING"
    end

  end
       
end
