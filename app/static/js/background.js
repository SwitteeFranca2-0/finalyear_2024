let phisher = document.querySelector('#phisher')
let check_btn = document.querySelector('#check')
let input = document.querySelector('#input')
let result_box = document.querySelector('#result_p')
let result_boxed = document.querySelector('#result')
let sliders = document.querySelectorAll('.slider')
let slider_box = document.querySelector('#slider_outer')





if (check_btn !== null) {
    check_btn.addEventListener('click', async () => {

        let url = input.value; 
        if (url == ''){
            result_boxed.style.display = 'flex';
            result_box.style.dispay = 'white';
            result_box.textContent = 'Please, input a link in the text box';

            return;
        }

        let inputData = {
            url: url
        };

        try {
            let response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(inputData)
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            let result = await response.json();
            console.log(result)
            result_boxed.style.display = 'flex'
            let extra_text = 'is safe to visit'
            if (result['result'] == 'Legitimate'){
                result_box.style.color = '#3cd73c'
            }
            else{
                result_box.style.color = '#ff1515'
                extra_text = ' is not safe. Do not Visit'
            }
            result_box.textContent = result['result'] + '; '+ ' ' + url + ' ' +extra_text
            input.value = '';
            // Do something with the result
        } catch (error) {
            console.error('There was a problem with the fetch operation:', error);
            // Handle error as needed
        }
    });
}

input.addEventListener('click', ()=>{
    input.value = '';
    result_box.textContent = '';
    result_boxed.style.display = 'none'
})


// window.addEventListener('resize', ()=>{
//     if (window.innerWidth >= 800){
//         if (sliders.length !== 0 && slider_box !== null){
//            sliders.forEach(slider =>{
//                slider.style.display = 'None';
//            })
//         }
//        }
    
//     if (window.innerWidth <= 800){
//     if (sliders.length !== 0 && slider_box !== null){
//         sliders.forEach(slider =>{
//             slider.style.display = 'block';
//         })
//     }
//     }
// })

// if (window.innerWidth >= 800){
//  if (sliders.length !== 0 && slider_box !== null){
//     sliders.forEach(slider =>{
//         slider.style.display = 'None';
//     })
//  }
// }



addAnimation = ()=>{
    slider_box.setAttribute('data-animated', true)
}

if (window.innerWidth >= 800){
    if (sliders.length > 0 && slider_box !== null){
      console.log('okay')
      if (!window.matchMedia("(prefers-reduced-motion: reduce").matches){
        addAnimation();
      }
    }
}

