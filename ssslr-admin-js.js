jQuery(function($){
	
	// options page accordion
	$('.ssslr-opts .accordion > h3 a').click(function(e){
		e.preventDefault();
		if(!$(this).hasClass('open')){
			$(this).closest('.accordion').children('h3').children('a').removeClass('open');
			$(this).addClass('open');
			$(this).closest('.accordion').children('div').slideUp(300);
			$(this).parent().next('div').slideDown(300);
		}
	});
	$('.ssslr-opts .accordion > div').slice(1).hide();
	
	// help icons
	$('.ssslr-opts a.open-accordion').click(function(e){
		e.preventDefault();
		var target = $(this).data('accordion-id');
		if($('#'+target).length == 1) $('#'+target).trigger('click');
	});
	
	// show/hide additional options
	$('.ssslr-opts input[name="ssslr_method"]').change(function(){
		if($(this).val() == 'off') $('.ssslr-opts .additional-options').slideUp(200);
		else $('.ssslr-opts .additional-options').slideDown(200);
	});
	
});