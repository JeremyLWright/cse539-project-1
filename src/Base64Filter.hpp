#include <string>
#include <iostream>

#include <boost/algorithm/cxx11/any_of.hpp>

#include <boost/iostreams/categories.hpp>
#include <boost/iostreams/operations.hpp>
#include <boost/iostreams/invert.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <sstream>
#include <string>
#include <exception>

typedef std::runtime_error base64_codec_exception;

/**
 * @class base64_output_encoder
 * @author Aaron Gibson
 *
 * This class implements a base64 encoder.
 */
class base64_output_encoder
{
private:
	//--------------------------------------------
	// Instance Variables
	//--------------------------------------------
	int32_t buffer; ///< Stores the buffer to load bytes into.
	unsigned short count; ///< Stores the number of characters left for the current block.

	/**
	 * getEncoding() Function
	 *
	 * This function returns the encoding for the given index.
	 * @param index -- The character to encode, between 0 and 63.
	 * @return -- The encoding of the given character.
	 * @throws base64_codec_exception
	 * @remarks
	 * Note that index MUST be between 0 and 63 or else an exception
	 * will be thrown!
	 */
	char getEncoding(char index)
	{
		static const char* table =  ///< This stores an array for the lookup table.
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789"
				"+/";
		//if(index < 0 || index > 63) {
		//	// Error!
		//}
		return static_cast< char >(table[index]);
	}

	/**
	 * reset() Function
	 *
	 * This function will reset the buffer and the counter for this filter. This
	 * will be called after a full block (3 characters) is processed in preparation
	 * for the next block.
	 */
	void reset()
	{
		buffer = 0;
		count = 3;
	}

	/**
	 * processBuffer() Function
	 * @param snk -- The instance to write data to.
	 * @param bytesToProcess -- The number of bytes to actually put to "snk".
	 * @tparam Sink -- A type that `boost::iostreams::put` can write to.
	 */
	template<typename Sink>
	void processBuffer(Sink& snk, int bytesToProcess = 4)
	{
		int i = 4;
		int end = 4 - bytesToProcess;
		char index;
		while (i > end) {
			--i;
			index = 0x3f & (buffer >> (6 * i));
			boost::iostreams::put(snk, getEncoding(index));
		}
	}
public:
	typedef char char_type; ///< Used by boost::iostreams to determine the character type.
	struct category :
		boost::iostreams::closable_tag,
		boost::iostreams::multichar_output_filter_tag
	{
	};

	/**
	 * base64_output_encoder Constructor
	 *
	 * This creates an instance of the output encoder for base64. This is a filter that
	 * can and should be used with `boost::iostreams` and associated filters.
	 */
	base64_output_encoder()
		: buffer(0), count(3)
	{
	}

	template<typename Sink>
	std::streamsize write(Sink& snk, const char* s, std::streamsize n)
	{
		std::streamsize i;
		for (i = 0; i < n; ++i) {
			// We try to read in three characters at a time, shifting them into the
			// "buffer" which is really just a 32bit integer. (Overflow is not an
			// issue because we only use 24 of the 32 bits.)
			--count;
			buffer |= (s[i] << (8 * count));
			if (count > 0) continue;

			// When we get the three characters, we can encode and print out four
			// hex-encoded characters, which is done in "processBuffer()".
			processBuffer(snk);

			// We also reset count to indicate how many more characters need to be
			// read before outputing the next set of 4 hex-encoded characters.
			// We also zero out the existing buffer.
			reset();
		}
		return i;
	}

	template<typename Sink>
	void close(Sink& snk)
	{
		// Close will be called when there are no more characters to read in.
		// We have to process as many remaining characters as we can, if any.
		if (count >= 3) return;
		processBuffer(snk, 4 - count);

		// Since Base64 requires chunks of 4 bytes, we have to "pad" our result with
		// '=' characters until we have a block of 4 bytes.
		while (count-- > 0) {
			boost::iostreams::put(snk, static_cast< char >('='));
		}
		reset();
	}
};
// class base64_encoder

class base64_output_decoder
{
private:
	char getDecoding(char ch)
	{
		if (ch >= 'A' && ch <= 'Z') {
			return static_cast< unsigned char >(ch - 'A');
		}
		if (ch >= 'a' && ch <= 'z') {
			return static_cast< unsigned char >((ch - 'a') + 26);
		}
		if (ch >= '0' && ch <= '9') {
			return static_cast< unsigned char >((ch - '0') + (26 * 2));
		}
		if (ch == '+') {
			return 62;
		}
		if (ch == '/') {
			return 63;
		}
		std::string msg(&ch, 1);
		throw base64_codec_exception("Invalid character during Base64 decode: " + msg);
		//return 0;
	}
	/**
	 * reset() Function
	 *
	 * This function will reset the buffer and the counter for this filter. This
	 * will be called after a full block (3 characters) is processed in preparation
	 * for the next block.
	 */
	void reset()
	{
		buffer = 0;
		count = 4;
		bytesToProcess = 3;
	}

public:
	typedef char char_type; ///< Used by boost::iostreams to determine the character type.
	struct category:
		boost::iostreams::closable_tag,
		boost::iostreams::multichar_output_filter_tag
	{
	};

	uint32_t buffer; ///< Stores a buffer to use for decoding.
	unsigned short count; ///< Stores the number of characters left to fill in the current block.
	int bytesToProcess; ///< Stores the number of bytes to process in the block.
	bool foundPadding; ///< Stores whether we have received a padding character.

	base64_output_decoder()
		: buffer(0), count(4), bytesToProcess(3), foundPadding(false)
	{
	}

	template<typename Sink>
	void processBlock(Sink& snk, int bytesToProcess = 3)
	{
		int i = 3;
		int end = 3 - bytesToProcess;
		char index;
		while (i > end) {
			--i;
			index = (0xff & (buffer >> (8 * i)));
			boost::iostreams::put(snk, static_cast< char >(index));
		}
	}

	template<typename Sink>
	std::streamsize write(Sink& snk, const char* s, std::streamsize n)
	{
		// Read in three characters.
		std::streamsize i;
		for (i = 0; i < n; ++i) {
			char ch = s[i];
			// Be nice and ignore whitespace entirely.
			if (boost::algorithm::any_of_equal(" \r\n\t", ch)) {
				continue;
			}
			--count;
			if (ch == '=') {
				// We have a padding character, which implies that we have one less
				// character to process.
				foundPadding = true;
				bytesToProcess--;
				continue;
			} else if (foundPadding) {
				throw base64_codec_exception(
					"Padding characters are only allowed at the end of the stream!");
			}
			ch = (0x3f & getDecoding(ch));
			buffer |= (ch << (6 * count));
			if (count > 0) continue;

			processBlock(snk, bytesToProcess);
			reset();
		}
		return i;
	}

	template<typename Sink>
	void close(Sink& snk)
	{
		if (count == 0) {
			processBlock(snk, bytesToProcess);
		} else if (count >= 4) {
			reset();
			return;
		} else {
			// Error: Base64 encoding should come in groups of 4!
			throw base64_codec_exception("Base64 Encoded data should come in groups of 4!");
		}
	}
};

typedef boost::iostreams::inverse< base64_output_decoder > base64_input_decoder;

inline void encode(std::istream& input, std::ostream& output)
{
	boost::iostreams::filtering_ostream out;
	out.push(base64_output_encoder());
	out.push(output);
	out << input.rdbuf() << std::flush;
}

inline void decode(std::istream& input, std::ostream& output)
{
	boost::iostreams::filtering_ostream out;
	out.push(base64_output_decoder());
	out.push(output);

	out << input.rdbuf() << std::flush;
}

inline std::string encodeToString(std::istream& input)
{
	std::ostringstream result;
	encode(input, result);
	return result.str();
}

inline std::string decodeToString(std::istream& input)
{
	std::ostringstream result;
	decode(input, result);
	return result.str();
}

inline std::string encodeToString(const std::string& input)
{
	std::istringstream stream(input);
	return encodeToString(stream);
}

inline std::string decodeToString(const std::string& input)
{
	std::istringstream stream(input);
	return decodeToString(stream);
}



