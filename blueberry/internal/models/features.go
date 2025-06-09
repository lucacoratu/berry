package data

import "fmt"

type RequestFeatures struct {
	UrlLength          int64   //The length of the url
	NumberParams       int64   //The number of parameters including the ones from url and from body
	NumberSpecialChars int64   //The number of special characters from the parameters
	RatioSpecialChars  float64 //The number of special chars divided by number of total chars

	NumberRoundBrackets  int64 //The number of ( or ) from the parameters
	NumberSquareBrackets int64 //The number of [ or ] brackets from the parameters
	NumberCurlyBrackets  int64 //The number of { or } from the parameters
	NumberApostrophes    int64 //The number of ' from the parameters
	NumberQuotationMarks int64 //The number of " from the parameters
	NumberDots           int64 //The number of . from the parameters
	NumberSlash          int64 //The number of / from the parameters
	NumberBackslash      int64 //The number of \ from the parameters
	NumberComma          int64 //The number of , from the parameters
	NumberColon          int64 //The number of : from the parameters
	NumberSemicolon      int64 //The number of ; from the parameters
	NumberMinus          int64 //The number of - from the parameters
	NumberPlus           int64 //The number of + from the parameters
	NumberLessGreater    int64 //The number of < and > from the parameters

	DistanceDots      float64 //Avg number of characters between succesive dots (.) from the parameters
	DistanceSlash     float64 //Avg number of characters between succesive slashes (/) from the parameters
	DistanceBackslash float64 //Avg number of characters between succesive backslashes (\) from the parameters
	DistanceComma     float64 //Avg number of characters between succesive commas (,) from the parameters
	DistanceColon     float64 //Avg number of characters between succesive colons (:) from the parameters
	DistanceSemicolon float64 //Avg number of characters between succesive semicolons (;) from the parameters
	DistanceMinus     float64 //Avg number of characters between succesive minuses (-) from the parameters
	DistancePlus      float64 //Avg number of characters between succesive pluses (+) from the parameters
}

func (features *RequestFeatures) ToString() string {
	return fmt.Sprintf(
		"%d,%d,%d,%f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f,%f",
		features.UrlLength,
		features.NumberParams,
		features.NumberSpecialChars,
		features.RatioSpecialChars,
		features.NumberRoundBrackets,
		features.NumberSquareBrackets,
		features.NumberCurlyBrackets,
		features.NumberApostrophes,
		features.NumberQuotationMarks,
		features.NumberDots,
		features.NumberSlash,
		features.NumberBackslash,
		features.NumberComma,
		features.NumberColon,
		features.NumberSemicolon,
		features.NumberMinus,
		features.NumberPlus,
		features.NumberLessGreater,
		features.DistanceDots,
		features.DistanceSlash,
		features.DistanceBackslash,
		features.DistanceComma,
		features.DistanceColon,
		features.DistanceSemicolon,
		features.DistanceMinus,
		features.DistancePlus,
	)
}
